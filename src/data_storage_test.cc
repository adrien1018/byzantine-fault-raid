#include "data_storage.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <thread>

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
    std::cout << "Running TestGetFileList...   " << std::flush;
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
    std::cout << "Running TestSimpleReadWrite...   " << std::flush;
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
    std::cout << "Running TestGetLatestVersion...   " << std::flush;
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
    std::cout << "Running TestExtendFile...   " << std::flush;
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
    std::cout << "Running TestOverlapExtend...   " << std::flush;
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
    std::cout << "Running TestSimpleMultipleWrite...   " << std::flush;
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

    assert(Bytes(version4.begin() + 5 * BLOCK_SIZE,
                 version4.begin() + 8 * BLOCK_SIZE) ==
               storage.ReadFile(file_name, 5, 3, 4) &&
           "Version 4 mismatched");
    assert(Bytes(version3.begin() + 2 * BLOCK_SIZE,
                 version3.begin() + 8 * BLOCK_SIZE) ==
               storage.ReadFile(file_name, 2, 6, 3) &&
           "Version 3 mismatched");
    assert(Bytes(version2.begin() + 3 * BLOCK_SIZE,
                 version2.begin() + 7 * BLOCK_SIZE) ==
               storage.ReadFile(file_name, 3, 4, 2) &&
           "Version 2 mismatched");
    assert(version1 == storage.ReadFile(file_name, 0, 10, 1) &&
           "Version 1 mismatched");

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestMultipleExtendWrite() {
    std::cout << "Running TestSimpleMultipleWrite...   " << std::flush;
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

void TestGarbageCollection() {
    std::cout << "Running TestGarbageCollection...   " << std::flush;
    std::string test_dir = "TestGarbageCollection";
    DataStorage storage(test_dir, BLOCK_SIZE);

    const std::string file_name{"temp"};
    storage.CreateFile(file_name, public_key);
    Bytes version1 = RandomStripe(file_name, 1, 0, 5);
    assert(storage.WriteFile(file_name, 0, 5, 0, 1, version1) &&
           "Write first failed");
    assert(Bytes(version1.begin() + BLOCK_SIZE,
                 version1.begin() + 3 * BLOCK_SIZE) ==
           storage.ReadFile(file_name, 1, 2, 1));

    Bytes version2 = RandomStripe(file_name, 2, 0, 10);
    assert(storage.WriteFile(file_name, 0, 10, 0, 2, version2) &&
           "Write second filed");

    std::this_thread::sleep_for(std::chrono::seconds(30) +
                                std::chrono::seconds(1));
    assert(storage.ReadFile(file_name, 0, 5, 1).empty() &&
           "Version 1 not deleted");

    Bytes version3 = RandomStripe(file_name, 3, 4, 12);
    assert(storage.WriteFile(file_name, 4, 12, 0, 3, version3) &&
           "Write third failed");

    assert(version2 == storage.ReadFile(file_name, 0, 10, 2));
    std::this_thread::sleep_for(std::chrono::seconds(30) +
                                std::chrono::seconds(1));
    assert(storage.ReadFile(file_name, 0, 10, 2).empty() &&
           "Version 2 not deleted");
    assert(version3 == storage.ReadFile(file_name, 4, 12, 3));

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestConcurrentReadWrite() {
    std::cout << "Running TestConcurrentReadWrite...   " << std::flush;
    std::string test_dir = "TestConcurrentReadWrite";
    DataStorage storage(test_dir, BLOCK_SIZE);

    const uint32_t num_readers = 10;
    const uint32_t max_version = 5;
    std::vector<std::vector<Bytes>> response(num_readers,
                                             std::vector<Bytes>(max_version));
    std::vector<Bytes> answers(max_version);
    std::vector<std::thread> readers;
    const std::string file_name{"temp"};

    auto Reader = [&](int idx) {
        for (uint32_t i = 0; i < max_version; i++) {
            Bytes content;
            do {
                content = storage.ReadFile(file_name, 0, 1, i + 1);
            } while (content.empty());
            response[idx][i] = content;
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

        std::this_thread::sleep_for(std::chrono::seconds(30) +
                                    std::chrono::seconds(1));
        for (uint32_t i = 0; i < max_version - 1; i++) {
            assert(storage.ReadFile(file_name, 0, 1, i + 1).empty());
        }
        assert(storage.ReadFile(file_name, 0, 1, max_version) ==
               response[idx][max_version - 1]);
    };

    storage.CreateFile(file_name, public_key);
    for (uint32_t i = 0; i < num_readers; i++) {
        readers.emplace_back(std::thread(Reader, i));
    }

    for (uint32_t i = 0; i < max_version; i++) {
        answers[i] = RandomStripe(file_name, i + 1, 0, 1);
        assert(storage.WriteFile(file_name, 0, 1, 0, i + 1, answers[i]));
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    for (uint32_t i = 0; i < num_readers; i++) {
        readers[i].join();
    }

    for (uint32_t i = 0; i < num_readers; i++) {
        for (uint32_t j = 0; j < max_version; j++) {
            assert(answers[j] == response[i][j]);
        }
    }

    std::cout << "Passed" << std::endl;
    fs::remove_all(test_dir);
}

void TestStorageBackup() {}

int main() {
    SetKey();
    TestGetFileList();
    TestSimpleReadWrite();
    TestGetLatestVersion();
    TestExtendFile();
    TestOverlapExtend();
    TestSimpleMultipleWrite();
    TestMultipleExtendWrite();
    TestGarbageCollection();
    TestConcurrentReadWrite();
}