/*
 * FUSE wrapper around the Byzantine Fault Raid file system.
 */

#include <random>
#include <fuse.h>
#include <spdlog/spdlog.h>

#include <CLI/CLI.hpp>

#include "BFRFileSystem.h"
#include "config.h"

static_assert(sizeof(off_t) == 8, "off_t must be 64 bits");

static std::unique_ptr<BFRFileSystem> bfrFs;

/// FUSE
static int bfr_unlink(const char *path) {
    const char *bfrPath = path + 1;
    spdlog::info("FUSE unlink: {}", bfrPath);
    return bfrFs->unlink(bfrPath);
}

#if FUSE_USE_VERSION >= 30
static int bfr_getattr(const char *path, struct stat *stbuf,
                       struct fuse_file_info *fi)
#else
static int bfr_getattr(const char *path, struct stat *stbuf)
#endif
{
    // TODO: Reimplement for pk directories
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        spdlog::info("FUSE getattr: {}", path);
        /* Root directory of our file system. */
        const size_t numFiles = bfrFs->getFileList().size();
        stbuf->st_mode = S_IFDIR | 0777;
        stbuf->st_nlink = numFiles;
        return 0;
    }

    const char *bfrPath = path + 1;  // Remove preceding '/'
    spdlog::info("FUSE getattr: {}", bfrPath);
    const std::optional<FileMetadata> metadata = bfrFs->open(bfrPath);
    if (metadata.has_value()) {
        /* File exists in our file system. */
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = metadata.value().fileSize;
        return 0;
    } else {
        /* File doesn't exist in our file system. */
        return -ENOENT;
    }
}

static int bfr_open(const char *path, struct fuse_file_info *info) {
    const char *bfrPath = path + 1;  // Remove preceding '/'
    spdlog::info("FUSE open: {}", bfrPath);
    const std::optional<FileMetadata> metadata = bfrFs->open(bfrPath);
    if (metadata.has_value()) {
        return 0;
    }
    if (info->flags & O_CREAT) {
        return bfrFs->create(bfrPath);
    }
    return -ENOENT;
}

// FUSE API does not support 64-bit.
static int bfr_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    const char *bfrPath = path + 1;
    spdlog::info("FUSE read: {}", bfrPath);
    return std::min(bfrFs->read(bfrPath, buf, size, offset),
                    (int64_t)std::numeric_limits<int>::max());
}

#if FUSE_USE_VERSION >= 30
static int bfr_readdir(const char *path, void *buf, fuse_fill_dir_t filler_arg,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
#else
static int bfr_readdir(const char *path, void *buf, fuse_fill_dir_t filler_arg,
                       off_t offset, struct fuse_file_info *fi)
#endif
{
    // TODO: Reimplement for pk directories
    spdlog::info("FUSE readdir: {}", path);
    if (strcmp(path, "/") != 0) {
        /* We only recognize the root directory. */
        return -ENOENT;
    }

    auto filler = [&filler_arg](void *buf, const char *name,
                                const struct stat *stbuf, off_t off) {
#if FUSE_USE_VERSION >= 30
        return filler_arg(buf, name, stbuf, off, FUSE_FILL_DIR_PLUS);
#else
        return filler_arg(buf, name, stbuf, off);
#endif
    };

    filler(buf, ".", NULL, 0);  /* Current directory. */
    filler(buf, "..", NULL, 0); /* Parent directory. */

    const std::unordered_set<std::string> fileList = bfrFs->getFileList();
    for (const std::string &filename : fileList) {
        filler(buf, filename.c_str(), NULL, 0);
    }

    return 0;
}

static int bfr_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *info) {
    const char *bfrPath = path + 1;
    spdlog::info("FUSE write: {}", bfrPath);
    return std::min(bfrFs->write(bfrPath, buf, size, offset),
                    (int64_t)std::numeric_limits<int>::max());
}

static void bfr_destroy(void *private_data) {
    /* Called on filesystem exit. Clean up filesystem. */
    bfrFs.reset();
}

static int bfr_create(const char *path, mode_t mode,
                      struct fuse_file_info *info) {
    const char *bfrPath = path + 1;  // Remove preceding '/'
    spdlog::info("FUSE create: {}", bfrPath);
    return bfrFs->create(bfrPath);
}

static struct fuse_operations bfr_filesystem_operations = {
    .getattr = bfr_getattr,
    .unlink = bfr_unlink,
    .open = bfr_open,
    .read = bfr_read,
    .write = bfr_write,
    .readdir = bfr_readdir,
    .destroy = bfr_destroy,
    .create = bfr_create};


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
