// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "AES.h"

#define EXPORTED_METHOD extern "C" __declspec(dllexport)

// Function to generate a random key for AES encryption
EXPORTED_METHOD unsigned char* GenerateKey(size_t* keyLen) {  // keyLen is a pointer to the key length
    try {
        // Initialize AES with 128-bit key length
        AES aes(AESKeyLength::AES_128);

        // Generate a random key of 16 bytes (128 bits) for AES-128
        std::vector<unsigned char> key = aes.generateKey(16); // Byte array key

        // Allocate memory for the key
        unsigned char* keyArray = new unsigned char[key.size()];
        std::memcpy(keyArray, key.data(), key.size());

        // Set the key length to the caller
        *keyLen = key.size();

        return keyArray;
    }
    catch (const std::exception&) {
        *keyLen = 0;
        return nullptr;
    }
}

// Function to encrypt plain text using AES encryption
// keyBytes is the key for encryption
// keyLen is the length of the key
// plainBytes is the plain text to be encrypted
// plainLen is the length of the plain text
EXPORTED_METHOD unsigned char* Encrypt(const unsigned char* keyBytes, size_t keyLen, const unsigned char* plainBytes, size_t plainLen, size_t* encryptedLen) {
    try {
        AES aes(AESKeyLength::AES_128);

        std::vector<unsigned char> keyVector(keyBytes, keyBytes + keyLen);
        std::vector<unsigned char> plainTextVector(plainBytes, plainBytes + plainLen);

        std::vector<unsigned char> paddingBytes = aes.padToBlockSize(plainTextVector, 16);
        std::vector<std::vector<unsigned char>> blocks = aes.divideIntoBlocks(paddingBytes, 16);

        std::vector<unsigned char> encryptedBytes;
        for (const auto& block : blocks) {
            auto encryptedBlock = aes.EncryptECB(block, keyVector);
            encryptedBytes.insert(encryptedBytes.end(), encryptedBlock.begin(), encryptedBlock.end());
        }

        *encryptedLen = encryptedBytes.size();
        unsigned char* encryptedArray = new unsigned char[encryptedBytes.size()];
        std::memcpy(encryptedArray, encryptedBytes.data(), encryptedBytes.size());

        return encryptedArray;
    }
    catch (const std::exception&) {
        *encryptedLen = 0;
        return nullptr;
    }
}

// Function to decrypt cipher text using AES decryption
EXPORTED_METHOD unsigned char* Decrypt(const unsigned char* keyBytes, size_t keyLen, const unsigned char* encryptedBytes, size_t encryptedLen, size_t* decryptedLen) {
    try {
        AES aes(AESKeyLength::AES_128);

        std::vector<unsigned char> keyVector(keyBytes, keyBytes + keyLen);
        std::vector<unsigned char> encryptedBytesVector(encryptedBytes, encryptedBytes + encryptedLen);

        std::vector<std::vector<unsigned char>> blocks = aes.divideIntoBlocks(encryptedBytesVector, 16);

        std::vector<unsigned char> decryptedBytes;
        for (const auto& block : blocks) {
            auto decryptedBlock = aes.DecryptECB(block, keyVector);
            decryptedBytes.insert(decryptedBytes.end(), decryptedBlock.begin(), decryptedBlock.end());
        }

        *decryptedLen = decryptedBytes.size();
        unsigned char* decryptedArray = new unsigned char[decryptedBytes.size()];
        std::memcpy(decryptedArray, decryptedBytes.data(), decryptedBytes.size());

        return decryptedArray;
    }
    catch (const std::exception&) {
        *decryptedLen = 0;
        return nullptr;
    }
}

// Function to free allocated memory
EXPORTED_METHOD void FreeMemory(unsigned char* ptr) {
    if (ptr != nullptr) {
        delete[] ptr;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
