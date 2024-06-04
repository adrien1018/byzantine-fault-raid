/*
 * FUSE wrapper around the Byzantine Fault Raid file system.
 */

#include <fuse.h>
#include <spdlog/spdlog.h>

#include <CLI/CLI.hpp>

#include "BFRFileSystem.h"
#include "config.h"
#include "spdlog/sinks/basic_file_sink.h"

static_assert(sizeof(off_t) == 8, "off_t must be 64 bits");

static std::unique_ptr<BFRFileSystem> bfrFs;

static int bfr_unlink(const char *path) { return bfrFs->unlink(path); }

#if FUSE_USE_VERSION >= 30
static int bfr_getattr(const char *path, struct stat *stbuf,
                       struct fuse_file_info *fi)
#else
static int bfr_getattr(const char *path, struct stat *stbuf)
#endif
{
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        /* Root directory of our file system. */
        const size_t numFiles = bfrFs->getFileList().size();
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = numFiles;
        return 0;
    }

    const std::optional<FileMetadata> metadata = bfrFs->open(path);
    if (metadata.has_value()) {
        /* File exists in our file system. */
        stbuf->st_mode = S_IFREG | 0744;
        stbuf->st_nlink = 1;
        stbuf->st_size = metadata.value().fileSize;
        return 0;
    } else {
        /* File doesn't exist in our file system. */
        return -ENOENT;
    }
}

static int bfr_open(const char *path, struct fuse_file_info *info) {
    const std::optional<FileMetadata> metadata = bfrFs->open(path);
    if (metadata.has_value()) {
        return 0;
    }
    if (info->flags & O_CREAT) {
        return bfrFs->create(path);
    }
    return -ENOENT;
}

// FUSE API does not support 64-bit.
static int bfr_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    return std::min(bfrFs->read(path, buf, size, offset),
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
    return std::min(bfrFs->write(path, buf, size, offset),
                    (int64_t)std::numeric_limits<int>::max());
}

static void bfr_destroy(void *private_data) {
    /* Called on filesystem exit. Clean up filesystem. */
    bfrFs.reset();
}

static struct fuse_operations bfr_filesystem_operations = {
    .getattr = bfr_getattr,
    .unlink = bfr_unlink,
    .open = bfr_open,
    .read = bfr_read,
    .write = bfr_write,
    .readdir = bfr_readdir,
    .destroy = bfr_destroy};

int main(int argc, char **argv) {
    CLI::App app;
    app.set_config("--config", "../config.toml")->required();

    CLI11_PARSE(app, argc, argv);

    const std::string configFile = app.get_config_ptr()->as<std::string>();
    const Config config = ParseConfig(configFile);

    //auto logger = spdlog::basic_logger_mt("client_logger", "logs/client.log");
    //spdlog::set_default_logger(logger);
    spdlog::set_pattern("[%t] %+");
    spdlog::set_level(spdlog::level::debug);

    /* Initialize BFR-fs connection. */
    bfrFs =
        std::make_unique<BFRFileSystem>(config.servers, config.num_malicious,
                                        config.num_faulty, config.block_size);

    bfrFs->create("hello.txt");
    auto file_list = bfrFs->getFileList();
    for (const auto &file_name : file_list) {
        std::cerr << file_name << '\n';
    }
    bfrFs->write("hello.txt", "Hello, World!", 13, 0);
    std::cerr << "Write returned\n";
    char buffer[100];
    bfrFs->read("hello.txt", buffer, 13, 0);
    std::cerr << buffer << '\n';

    // return fuse_main(fuse_argc, fuse_argv, &bfr_filesystem_operations, NULL);
}
