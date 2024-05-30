/*
 * FUSE wrapper around the Byzantine Fault Raid file system.
 */

#include <fuse.h>
#include "CLI11.hh"
#include "config.h"

#include "BFRFileSystem.h"

static BFRFileSystem bfrFs;

static int
bfr_unlink(const char *path)
{
    return bfrFs.unlink(path);
}

static int
bfr_getattr(const char *path, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0)
    {
        /* Root directory of our file system. */
        const size_t numFiles = bfrFs.getFileList().size();
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = numFiles;
        return 0;
    }

    const std::optional<Metadata> metadata = bfrFs.open(path);
    if (metadata.has_value())
    {
        /* File exists in our file system. */
        stbuf->st_mode = S_IFREG | 0744;
        stbuf->st_nlink = 1;
        stbuf->st_size = metadata.value().filesize;
        return 0;
    }
    else
    {
        /* File doesn't exist in our file system. */
        return -ENOENT;
    }
}

static int
bfr_open(const char *path, struct file_fuse_info *info)
{
    if (info->flags & O_CREAT)
    {
        return bfrFs.create(path);
    }

    const std::optional<Metadata> metadata = bfrFs.open(path);
    if (metadata.hasValue())
    {
        return 0;
    }
    else
    {
        return -ENOENT;
    }
}

static int
bfr_read(const char *path, char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi)
{
    uint32_t version;
    const int bytesRead = bfrFs.read(path, buf, size, offset, version);
    return bytesRead;
}

static int
bfr_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
            struct fuse_file_info *fi)
{
    if (strcmp(path, "/") != 0) {
        /* We only recognize the root directory. */
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0);  /* Current directory. */
    filler(buf, "..", NULL, 0); /* Parent directory. */

    const std::vector<std::string> fileList = bfrFs.getFileList();
    for (const std::string &filename : fileList)
    {
        filler(buf, filename, NULL, 0);
    }

    return 0;
}

static int bfr_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *info)
{
    return bfrFs.write(path, buf, size, offset);
}

static struct fuse_operations bfr_filesystem_operations = {
    .unlink  = bfr_unlink,
    .getattr = bfr_getattr,
    .open    = bfr_open,
    .read    = bfr_read,
    .readdir = bfr_readdir,
    .write   = bfr_write,
};

int
main(int argc, char **argv)
{
    CLI::App app;
    app.set_config("--config", "../config.toml")->required();

    CLI11_PARSE(filesys, argc, argv);

    const std::string configFile = app.get_config_ptr()->as<std::string>();
    const Config config = ParseConfig(configFile);

    /* Initialize BFR-fs connection. */
    bfrFs = new BFRFileSystem(config.servers, config.num_malicious,
                              config.num_faulty, config.block_size);

    return fuse_main(argc, argv, &bfr_filesystem_operations, NULL);
}

