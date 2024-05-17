#include "data_storage.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <unordered_map>

namespace fs = std::filesystem;

const std::string dummy_key =
    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH7whVnaRnci7/"
    "72LXldOpnxfuet9Cl1ktW4D0u47Psd0Ob049F+Nvpv19AJP7VTMaCSuMIsWkR322/"
    "w4TszDvhQ+4vuVj33l+14YKfan03qff37jG6w/GZ8JBNzkU9FgwUTGT+tY5SDJ3Tmo/"
    "uuLKePg1OZ11q8BByKwS7SxUVAgMBAAE=";

Bytes RandomBlock(int size = BLOCK_SIZE) {
    Bytes block(size);
    for (auto& byte : block) {
        byte = rand() % static_cast<int>(std::numeric_limits<uint8_t>::max());
    }
    return block;
}

void TestGetFileList() {
    std::cout << "Running TestGetFileList...   ";
    std::string test_dir = "TestGetFileList";
    std::vector<std::string> file_list{"a", "b", "c", "d"};
    DataStorage storage(test_dir);
    for (const auto& file_name : file_list) {
        assert(storage.CreateFile(file_name, dummy_key) && "CreateFile failed");
    }

    auto retrieved_file_list = storage.GetFileList();
    assert(retrieved_file_list.size() == file_list.size() &&
           "File list length mismatch");

    for (const auto& file : retrieved_file_list) {
        assert(std::find(file_list.begin(), file_list.end(),
                         file->FileName()) != file_list.end() &&
               "File not found.");
        assert(file->Version() == 0 && "Version incorrect");
        Bytes public_key = file->PublicKey();
        assert(std::string(public_key.begin(), public_key.end()) == dummy_key &&
               "Public key mismatch");
    }

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestSimpleReadWrite() {
    std::cout << "Running TestSimpleReadWrite...   ";
    std::string test_dir = "TestSimpleReadWrite";
    DataStorage storage(test_dir);

    storage.CreateFile("temp", dummy_key);
    Bytes block = RandomBlock();
    storage.WriteFile("temp", 0, 1, 1, block);
    Bytes retrieved_block = storage.ReadFile("temp", 1);
    assert(block == retrieved_block && "Block mismatch");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestGetLatestVersion() {
    std::cout << "Running TestGetLatestVersion...   ";
    std::string test_dir = "TestGetLatestVersion";
    DataStorage storage(test_dir);

    std::vector<std::string> file_list{"a", "b", "c", "d"};

    for (const auto& file_name : file_list) {
        storage.CreateFile(file_name, dummy_key);
    }

    for (const auto& file_name : file_list) {
        uint32_t update_num = rand() % 9 + 1;
        Bytes block;
        for (uint32_t i = 0; i < update_num; i++) {
            block = RandomBlock();
            assert(storage.WriteFile(file_name, 0, 1, i + 1, block) &&
                   "Write failed");
        }
        assert(update_num == storage.GetLatestVersion(file_name) &&
               "Latest version mismatched");
        Bytes retrieved_block = storage.ReadFile(file_name, update_num);
        assert(block == retrieved_block && "Block mismatch");
    }
    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestExtendFile() {
    std::cout << "Running TestExtendFile...   ";
    std::string test_dir = "TestExtendFile";
    DataStorage storage(test_dir);

    storage.CreateFile("temp", dummy_key);
    Bytes block = RandomBlock();
    assert(storage.WriteFile("temp", 0, 1, 1, block) && "Write first fail");
    assert(block == storage.ReadFile("temp", 1) && "Read fail 1");

    Bytes block1 = RandomBlock(2 * BLOCK_SIZE);
    assert(storage.WriteFile("temp", 1, 2, 2, block1) && "Write second fail");
    block.insert(block.end(), block1.begin(), block1.end());
    assert(block == storage.ReadFile("temp", 2) && "Read fail 2");

    Bytes block2 = RandomBlock(4 * BLOCK_SIZE);
    assert(storage.WriteFile("temp", 3, 4, 3, block2) && "Write third fail");
    block.insert(block.end(), block2.begin(), block2.end());
    assert(block == storage.ReadFile("temp", 3) && "Read fail 3");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

int main() {
    TestGetFileList();
    TestSimpleReadWrite();
    TestGetLatestVersion();
    TestExtendFile();
}