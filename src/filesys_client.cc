/*
 * FUSE wrapper around the Byzantine Fault Raid file system.
 */
#ifdef __INTELLISENSE__
#define FUSE_USE_VERSION 31
#endif
#include <random>
#include <fuse.h>
#include <spdlog/spdlog.h>

#include <CLI/CLI.hpp>

#include "BFRFileSystem.h"
#include "config.h"

static_assert(sizeof(off_t) == 8, "off_t must be 64 bits");

namespace {

std::unique_ptr<BFRFileSystem> bfrFs;
std::map<std::string, size_t> directory_list;

inline std::string Parent(const std::string &path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? "" : path.substr(0, pos);
}

void UpdateDirectoryList(const std::unordered_set<std::string> &fileList) {
    std::string prefix = bfrFs->GetPrefix();
    prefix.pop_back();
    directory_list[prefix] = 0;
    for (auto& i : directory_list) i.second = 0;
    // count file childs
    for (const std::string& filename : fileList) {
        std::string directory = filename;
        for (size_t i = 0; directory.size(); i++) {
            directory = Parent(directory);
            if (i == 0) {
                directory_list[directory]++;
            } else {
                // add directory so the last loop won't insert anything
                directory_list[directory] = 0;
            }
        }
    }
    // add directory child count
    for (const auto& dir : directory_list) {
        if (dir.first.empty()) continue;
        directory_list[Parent(dir.first)]++;
    }
}

bool IsOwner(const std::string &path, bool include_self = false) {
    if (include_self && path + '/' == bfrFs->GetPrefix()) {
        return true;
    }
    return bfrFs->CheckPrefix(path);
}

/// FUSE
int bfr_unlink(const char *path) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE unlink: {}", pathStr);
    return bfrFs->unlink(pathStr);
}

#if FUSE_USE_VERSION >= 30
static int bfr_getattr(const char *path, struct stat *stbuf,
                       struct fuse_file_info *fi)
#else
static int bfr_getattr(const char *path, struct stat *stbuf)
#endif
{
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE getattr: {}", pathStr);

    memset(stbuf, 0, sizeof(struct stat));
    // Check if it is a file
    if (!pathStr.empty()) {
        const std::optional<FileMetadata> metadata = bfrFs->open(pathStr);
        if (metadata.has_value()) {
            /* File exists in our file system. */
            stbuf->st_mode = S_IFREG | (IsOwner(pathStr) ? 0644 : 0444);
            stbuf->st_nlink = 1;
            stbuf->st_size = metadata.value().fileSize;
            stbuf->st_gid = getgid();
            stbuf->st_uid = getuid();
            return 0;
        }
    }

    // Directory
    UpdateDirectoryList(bfrFs->getFileList());
    if (auto it = directory_list.find(pathStr); it != directory_list.end()) {
        stbuf->st_mode = S_IFDIR | (IsOwner(pathStr, true) ? 0755 : 0555);
        stbuf->st_nlink = 2 + it->second;
        stbuf->st_gid = getgid();
        stbuf->st_uid = getuid();
        return 0;
    }
    return -ENOENT;
}

int bfr_open(const char *path, struct fuse_file_info *info) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE open: {}", pathStr);
    const std::optional<FileMetadata> metadata = bfrFs->open(pathStr);
    if (metadata.has_value()) {
        return 0;
    }
    if (info->flags & O_CREAT) {
        return bfrFs->create(pathStr);
    }
    return -ENOENT;
}

// FUSE API does not support 64-bit.
int bfr_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE read: {}", pathStr);
    return std::min(bfrFs->read(pathStr, buf, size, offset),
                    (int64_t)std::numeric_limits<int>::max());
}

#if FUSE_USE_VERSION >= 30
int bfr_readdir(const char *path, void *buf, fuse_fill_dir_t filler_arg,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
#else
int bfr_readdir(const char *path, void *buf, fuse_fill_dir_t filler_arg,
                       off_t offset, struct fuse_file_info *fi)
#endif
{
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE readdir: {}", pathStr);
    auto fileList = bfrFs->getFileList();
    UpdateDirectoryList(fileList);

    for (auto& i : directory_list) {
        spdlog::debug("dir: {} {}", i.first, i.second);
    }

    auto it = directory_list.find(pathStr);
    if (it == directory_list.end()) {
        return -ENOENT;
    }

    auto filler = [&filler_arg](void *buf, const char *name,
                                const struct stat *stbuf, off_t off) {
        spdlog::debug("filler {}", name);
#if FUSE_USE_VERSION >= 30
        return filler_arg(buf, name, stbuf, off, FUSE_FILL_DIR_PLUS);
#else
        return filler_arg(buf, name, stbuf, off);
#endif
    };

    filler(buf, ".", nullptr, 0);  /* Current directory. */
    filler(buf, "..", nullptr, 0); /* Parent directory. */
    if (pathStr.size()) pathStr += '/';
    for (auto& i : fileList) {
        if (i.substr(0, pathStr.size()) != pathStr) continue;
        std::string name = i.substr(pathStr.size());
        if (name.find('/') == std::string::npos) {
            filler(buf, name.c_str(), nullptr, 0);
        }
    }
    for (auto nit = directory_list.upper_bound(pathStr); nit != directory_list.end(); nit++) {
        if (nit->first.substr(0, pathStr.size()) != pathStr) break;
        std::string name = nit->first.substr(pathStr.size());
        if (name.find('/') == std::string::npos) {
            filler(buf, name.c_str(), nullptr, 0);
        }
    }
    return 0;
}

int bfr_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *info) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE write: {}", pathStr);
    return std::min(bfrFs->write(pathStr, buf, size, offset),
                    (int64_t)std::numeric_limits<int>::max());
}

void bfr_destroy(void *private_data) {
    /* Called on filesystem exit. Clean up filesystem. */
    bfrFs.reset();
}

int bfr_create(const char *path, mode_t mode,
                      struct fuse_file_info *info) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE create: {}", pathStr);
    return bfrFs->create(pathStr);
}

int bfr_mkdir(const char* path, mode_t mode) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE mkdir: {}", pathStr);
    if (!IsOwner(pathStr)) {
        return -EACCES;
    }
    UpdateDirectoryList(bfrFs->getFileList());
    auto parent = Parent(pathStr);
    auto parent_it = directory_list.find(Parent(pathStr));
    if (parent_it == directory_list.end()) {
        return -ENOENT;
    }
    if (!directory_list.insert({pathStr, 0}).second) {
        return -EEXIST;
    }
    parent_it->second++;
    return 0;
}

int bfr_rmdir(const char* path) {
    std::string pathStr(path[0] ? path + 1 : path);
    spdlog::info("FUSE rmdir: {}", pathStr);
    if (!IsOwner(pathStr)) {
        return -EACCES;
    }
    UpdateDirectoryList(bfrFs->getFileList());
    auto it = directory_list.find(pathStr);
    if (it == directory_list.end()) {
        return -ENOENT;
    }
    if (it->second != 0) {
        return -ENOTEMPTY;
    }
    directory_list.erase(it);
    directory_list[Parent(pathStr)]--;
    return 0;
}

struct fuse_operations bfr_filesystem_operations = {
    .getattr = bfr_getattr,
    .mkdir = bfr_mkdir,
    .unlink = bfr_unlink,
    .rmdir = bfr_rmdir,
    .open = bfr_open,
    .read = bfr_read,
    .write = bfr_write,
    .readdir = bfr_readdir,
    .destroy = bfr_destroy,
    .create = bfr_create};

}  // namespace


int main(int argc, char **argv) {
    CLI::App app;
    app.set_config("--config", "../config.toml");

    std::string signing_key;
    app.add_option("-k,--key", signing_key, "Absolute or relative path")
        ->required();

    std::string fuse_mount_point; /* Absolute or relative path */
    app.add_option("-m,--mount_point", fuse_mount_point,
                   "Absolute or relative path");

    int index = 0;
    bool debug = false;
    app.add_option("-i,--index", index);
    app.add_flag("-d,--debug", debug, "Enable debug mode");

    CLI11_PARSE(app, argc, argv);

    const std::string configFile = app.get_config_ptr()->as<std::string>();
    const Config config = ParseConfig(configFile);

    spdlog::set_pattern("[%t] %+");
    spdlog::set_level(spdlog::level::debug);

    /* Initialize BFR-fs connection. */
    bfrFs = std::make_unique<BFRFileSystem>(config, signing_key);

    if (!debug) {
        if (fuse_mount_point.empty()) {
            spdlog::error("FUSE mount point not provided");
            return 1;
        }
        const int fuse_argc = 3;
        const char *fuse_argv[] = {
            argv[0],
            (char *) fuse_mount_point.c_str(),
            "-f"
        };
        return fuse_main(fuse_argc, (char**)fuse_argv, &bfr_filesystem_operations, nullptr);
    } else {
        auto prefix = bfrFs->GetPrefix();

        std::vector<std::string> files{"a.txt", "b.txt", "c.txt"};
        for (auto& i : files) i = prefix + i;

        bfrFs->create(files[index]);

        std::mt19937_64 gen;
        using mrand = std::uniform_int_distribution<int>;

        bool deleted = false;
        const int write_size = 1000;
        char buf[write_size] = {};
        std::string last_wrote;
        for (int i = 0; i < 300; i++) {
            int op = gen() % 4;
            spdlog::debug("op: {}", op);
            switch (op) {
                case 0: {
                    auto file_list = bfrFs->getFileList();
                    for (const auto &file_name : file_list) {
                        assert(std::find(files.begin(), files.end(), file_name) != files.end());
                    }
                } break;
                case 1: {
                    std::memset(buf, 0, sizeof(buf));
                    int file_index = rand() % files.size();
                    int start = mrand(0, 1000)(gen);
                    int end = mrand(0, 1000)(gen);
                    if (start > end) std::swap(start, end);
                    bool ret = bfrFs->read(files[file_index], buf, end - start, start);
                    if (file_index == index) {
                        if (last_wrote.empty()) {
                            assert(!ret);
                        } else {
                            if (!(ret && std::string(buf, buf + (end - start)) == last_wrote.substr(start, end - start))) {
                                spdlog::error("Wrote: {}", last_wrote.substr(start, end - start));
                                spdlog::error("Read: {}", std::string(buf, buf + (end - start)));
                                assert(false);
                            }
                        }
                    }
                } break;
                case 2: {
                    if (deleted) {
                        bfrFs->create(files[index]);
                        deleted = false;
                    }
                    for (int i = 0; i < write_size; i++) {
                        buf[i] = mrand('a', 'z')(gen);
                    }
                    bfrFs->write(files[index], (char*)buf, write_size, 0);
                    last_wrote = std::string(buf, buf + write_size);
                    //spdlog::debug("Wrote: {}", last_wrote);
                } break;
                case 3: {
                    if (deleted) {
                        bfrFs->create(files[index]);
                        deleted = false;
                    } else {
                        // bfrFs->unlink(files[index]);
                        // deleted = true;
                    }
                } break;
            }
        }
    }
}
