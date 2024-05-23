#include "data_storage.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>

#include "encode_decode.h"
#include "signature.h"

#define BLOCK_SIZE 128
#define SIG_SIZE 64

namespace fs = std::filesystem;

SigningKey private_key;
Bytes public_key;

void SetKey() {
    private_key = SigningKey();
    public_key = private_key.PublicKey();
}

Bytes RandomBlock(const std::string& file_name, int version, int stripe_id) {
    Bytes block(BLOCK_SIZE - SIG_SIZE);
    for (auto& byte : block) {
        byte = rand() % static_cast<int>(std::numeric_limits<uint8_t>::max());
    }

    std::vector<Bytes> result =
        Encode(block, 1, 0, private_key, file_name, stripe_id, version);
    assert(VerifyBlock(result[0], 0, SigningKey(public_key, false), file_name,
                       stripe_id, version));
    return result[0];
}

Bytes RandomStripe(const std::string& file_name, int version, int stripe_offset,
                   int num_stripe) {
    Bytes stripe(num_stripe * BLOCK_SIZE);
    for (int i = 0; i < num_stripe; i++) {
        Bytes block = RandomBlock(file_name, version, stripe_offset + i);
        std::copy(block.begin(), block.end(),
                  stripe.begin() + (i * BLOCK_SIZE));
    }
    return stripe;
}

void TestGetFileList() {
    std::cout << "Running TestGetFileList...   ";
    std::string test_dir = "TestGetFileList";
    std::vector<std::string> file_list{"a", "b", "c", "d"};
    DataStorage storage(test_dir, BLOCK_SIZE);
    for (const auto& file_name : file_list) {
        assert(storage.CreateFile(file_name, public_key) &&
               "CreateFile failed");
    }

    auto retrieved_file_list = storage.GetFileList();
    assert(retrieved_file_list.size() == file_list.size() &&
           "File list length mismatch");

    for (const auto& file : retrieved_file_list) {
        assert(std::find(file_list.begin(), file_list.end(),
                         file->FileName()) != file_list.end() &&
               "File not found.");
        assert(file->Version() == 0 && "Version incorrect");
        Bytes pkey = file->PublicKey();
        assert(pkey == public_key && "Public key mismatch");
    }

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestSimpleReadWrite() {
    std::cout << "Running TestSimpleReadWrite...   ";
    std::string test_dir = "TestSimpleReadWrite";
    DataStorage storage(test_dir, BLOCK_SIZE);

    std::string file_name{"temp"};
    storage.CreateFile(file_name, public_key);
    Bytes stripe = RandomStripe(file_name, 1, 0, 1);
    storage.WriteFile("temp", 0, 1, 0, 1, stripe);
    Bytes retrieved_stripe = storage.ReadFile("temp", 0, 1, 1);
    assert(stripe == retrieved_stripe && "Block mismatch");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestGetLatestVersion() {
    std::cout << "Running TestGetLatestVersion...   ";
    std::string test_dir = "TestGetLatestVersion";
    DataStorage storage(test_dir, BLOCK_SIZE);

    std::vector<std::string> file_list{"a", "b", "c", "d"};

    for (const auto& file_name : file_list) {
        storage.CreateFile(file_name, public_key);
    }

    for (const auto& file_name : file_list) {
        uint32_t update_num = rand() % 9 + 1;
        Bytes stripe;
        for (uint32_t i = 0; i < update_num; i++) {
            stripe = RandomStripe(file_name, i + 1, 0, 1);
            assert(storage.WriteFile(file_name, 0, 1, 0, i + 1, stripe) &&
                   "Write failed");
        }
        assert(update_num == storage.GetLatestVersion(file_name) &&
               "Latest version mismatched");
        Bytes retrieved_stripe = storage.ReadFile(file_name, 0, 1, update_num);
        assert(stripe == retrieved_stripe && "Block mismatch");
    }
    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestExtendFile() {
    std::cout << "Running TestExtendFile...   ";
    std::string test_dir = "TestExtendFile";
    DataStorage storage(test_dir, BLOCK_SIZE);

    std::string file_name{"temp"};
    storage.CreateFile(file_name, public_key);
    Bytes stripe = RandomStripe(file_name, 1, 0, 1);
    assert(storage.WriteFile(file_name, 0, 1, 0, 1, stripe) &&
           "Write first failed");
    assert(stripe == storage.ReadFile(file_name, 0, 1, 1) && "Read fail 1");

    Bytes stripe1 = RandomStripe(file_name, 2, 1, 2);
    assert(storage.WriteFile(file_name, 1, 2, 0, 2, stripe1) &&
           "Write second failed");
    stripe.insert(stripe.end(), stripe1.begin(), stripe1.end());
    assert(stripe == storage.ReadFile(file_name, 0, 3, 2) && "Read fail 2");

    Bytes stripe2 = RandomStripe(file_name, 3, 3, 4);
    assert(storage.WriteFile(file_name, 3, 4, 0, 3, stripe2) &&
           "Write third failed");
    stripe.insert(stripe.end(), stripe2.begin(), stripe2.end());
    assert(stripe == storage.ReadFile(file_name, 0, 7, 3) && "Read fail 3");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestOverlapExtend() {
    std::cout << "Running TestOverlapExtend...   ";
    std::string test_dir = "TestOverlapExtend";
    DataStorage storage(test_dir, BLOCK_SIZE);

    const std::string& file_name{"temp"};
    storage.CreateFile(file_name, public_key);
    Bytes stripe = RandomStripe(file_name, 1, 0, 2);
    assert(storage.WriteFile(file_name, 0, 2, 0, 1, stripe) &&
           "Write first failed");
    assert(stripe == storage.ReadFile(file_name, 0, 2, 1) && "Read fail 1");

    Bytes stripe2 = RandomStripe(file_name, 2, 1, 2);
    assert(storage.WriteFile(file_name, 1, 2, 0, 2, stripe2) &&
           "Write second failed ");
    stripe.resize(BLOCK_SIZE);
    stripe.insert(stripe.end(), stripe2.begin(), stripe2.end());
    assert(stripe == storage.ReadFile(file_name, 0, 3, 2) && "Read fail 2");

    Bytes stripe3 = RandomStripe(file_name, 3, 2, 4);
    assert(storage.WriteFile(file_name, 2, 4, 0, 3, stripe3) &&
           "Write third failed");
    stripe.resize(2 * BLOCK_SIZE);
    stripe.insert(stripe.end(), stripe3.begin(), stripe3.end());
    assert(stripe == storage.ReadFile(file_name, 0, 6, 3) && "Read fail 3");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestSimpleMultipleWrite() {
    std::cout << "Running TestSimpleMultipleWrite...   ";
    std::string test_dir = "TestSimpleMultipleWrite";
    DataStorage storage(test_dir, BLOCK_SIZE);

    const std::string file_name{"temp"};
    storage.CreateFile(file_name, public_key);
    Bytes version1 = RandomStripe(file_name, 1, 0, 10);
    assert(storage.WriteFile(file_name, 0, 10, 0, 1, version1) &&
           "Write first failed");

    uint32_t stripe_offset = 2;
    Bytes update2 = RandomStripe(file_name, 2, stripe_offset, 2);
    Bytes version2 = version1;
    for (uint32_t i = 0; i < update2.size(); i++) {
        version2[stripe_offset * BLOCK_SIZE + i] = update2[i];
    }
    assert(storage.WriteFile(file_name, stripe_offset, 2, 0, 2, update2) &&
           "Write second failed");

    stripe_offset = 5;
    Bytes update3 = RandomStripe(file_name, 3, stripe_offset, 4);
    Bytes version3 = version2;
    for (uint32_t i = 0; i < update3.size(); i++) {
        version3[stripe_offset * BLOCK_SIZE + i] = update3[i];
    }
    assert(storage.WriteFile(file_name, stripe_offset, 4, 0, 3, update3));

    Bytes version4 = RandomStripe(file_name, 4, 0, 10);
    assert(storage.WriteFile(file_name, 0, 10, 0, 4, version4) &&
           "Write four failed");

    assert(version4 == storage.ReadFile(file_name, 0, 10, 4) &&
           "Version 4 mismatched");
    assert(version3 == storage.ReadFile(file_name, 0, 10, 3) &&
           "Version 3 mismatched");
    assert(version2 == storage.ReadFile(file_name, 0, 10, 2) &&
           "Version 2 mismatched");
    assert(version1 == storage.ReadFile(file_name, 0, 10, 1) &&
           "Version 1 mismatched");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestMultipleExtendWrite() {
    std::cout << "Running TestSimpleMultipleWrite...   ";
    std::string test_dir = "TestSimpleMultipleWrite";
    DataStorage storage(test_dir, BLOCK_SIZE);

    const std::string file_name{"temp"};
    storage.CreateFile(file_name, public_key);
    Bytes version1 = RandomStripe(file_name, 1, 0, 1);
    assert(storage.WriteFile(file_name, 0, 1, 0, 1, version1) &&
           "Write first failed");

    Bytes update2 = RandomStripe(file_name, 2, 1, 1);
    Bytes version2 = version1;
    version2.insert(version2.end(), update2.begin(), update2.end());
    assert(storage.WriteFile(file_name, 1, 1, 0, 2, update2) &&
           "Write second failed");

    Bytes update3 = RandomStripe(file_name, 3, 1, 2);
    Bytes version3 = version2;
    version3.resize(BLOCK_SIZE);
    version3.insert(version3.end(), update3.begin(), update3.end());
    assert(storage.WriteFile(file_name, 1, 2, 0, 3, update3) &&
           "Write third failed");

    assert(version3 == storage.ReadFile(file_name, 0, 3, 3) &&
           "Version 3 mismatched");
    assert(version2 == storage.ReadFile(file_name, 0, 2, 2) &&
           "Version 2 mismatched");
    assert(version1 == storage.ReadFile(file_name, 0, 1, 1) &&
           "Version 1 mismatched");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

int main() {
    SetKey();
    TestGetFileList();
    TestSimpleReadWrite();
    TestGetLatestVersion();
    TestExtendFile();
    TestOverlapExtend();
    TestSimpleMultipleWrite();
    TestMultipleExtendWrite();
}