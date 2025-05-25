#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <filesystem>
#include <cstring>
#include <chrono>
#include <memory>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>

using namespace CryptoPP;

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

enum class OperationType
{
    GENERATE,
    ENCRYPT,
    DECRYPT,
    HELP,
    UNKNOWN
};

enum class ModeType
{
    ECB,
    CBC,
    OFB,
    CFB,
    CTR,
    XTS,
    CCM,
    GCM,
    UNKNOWN
};

extern "C"
{
    EXPORT std::pair<size_t, size_t> GetKeyIVSize(ModeType mode, size_t aesKeySize);
    EXPORT void generateKeyIV(SecByteBlock &key, SecByteBlock &iv, size_t keySize, size_t ivSize);
    EXPORT void saveKeyIVToFile(const char *filename, const SecByteBlock &key, const SecByteBlock &iv);
    EXPORT size_t loadKeyIVFromFile(const char *filename, SecByteBlock &key, SecByteBlock &iv, size_t expectedKeySize);
    EXPORT bool LoadDataFromFile(const char *filename, std::vector<byte> &data);
    EXPORT void SaveDataToFile(const char *filename, const byte *data, size_t dataSize);
    EXPORT bool AESEncrypt(
        ModeType mode,
        const SecByteBlock &key,
        const SecByteBlock &iv,
        const byte *plaintext, size_t plaintextLen,
        byte *cipherBuffer, size_t *cipherLen);
    EXPORT bool AESDecrypt(
        ModeType mode,
        const SecByteBlock &key,
        const SecByteBlock &iv,
        const byte *ciphertext, size_t cipherLen,
        byte *plaintextBuffer, size_t *plaintextLen);
    EXPORT ModeType parseMode(const char *modeStr);
    EXPORT OperationType parseOperation(const char *opStr);
}

// Constants
const int GCM_TAG_SIZE = 16;
const int CCM_TAG_SIZE = 16;

OperationType parseOperation(const char *opStr)
{
    if (!opStr)
        return OperationType::UNKNOWN;
    if (strcmp(opStr, "--generate") == 0)
        return OperationType::GENERATE;
    if (strcmp(opStr, "--encrypt") == 0)
        return OperationType::ENCRYPT;
    if (strcmp(opStr, "--decrypt") == 0)
        return OperationType::DECRYPT;
    if (strcmp(opStr, "--help") == 0)
        return OperationType::HELP;
    return OperationType::UNKNOWN;
}

ModeType parseMode(const char *modeStr)
{
    if (!modeStr)
        return ModeType::UNKNOWN;
    if (strcmp(modeStr, "ECB") == 0)
        return ModeType::ECB;
    if (strcmp(modeStr, "CBC") == 0)
        return ModeType::CBC;
    if (strcmp(modeStr, "OFB") == 0)
        return ModeType::OFB;
    if (strcmp(modeStr, "CFB") == 0)
        return ModeType::CFB;
    if (strcmp(modeStr, "CTR") == 0)
        return ModeType::CTR;
    if (strcmp(modeStr, "XTS") == 0)
        return ModeType::XTS;
    if (strcmp(modeStr, "CCM") == 0)
        return ModeType::CCM;
    if (strcmp(modeStr, "GCM") == 0)
        return ModeType::GCM;
    return ModeType::UNKNOWN;
}

std::pair<size_t, size_t> GetKeyIVSize(ModeType mode, size_t aesKeySize)
{
    size_t keySize = aesKeySize;
    size_t ivSize = AES::BLOCKSIZE;
    switch (mode)
    {
    case ModeType::ECB:
        ivSize = 0;
        break;
    case ModeType::XTS:
        if (aesKeySize == 16)
            keySize = 32;
        else if (aesKeySize == 24)
            keySize = 48;
        else if (aesKeySize == 32)
            keySize = 64;
        else
            throw std::runtime_error("Invalid AES key size specified for XTS (must be 16, 24, or 32).");
        ivSize = AES::BLOCKSIZE;
        break;
    case ModeType::CCM:
        ivSize = 12; // Typical CCM nonce size
        break;
    case ModeType::GCM:
        ivSize = 12; // Typical GCM nonce size
        break;
    case ModeType::CBC:
    case ModeType::OFB:
    case ModeType::CFB:
    case ModeType::CTR:
        ivSize = AES::BLOCKSIZE;
        break;
    default:
        throw std::runtime_error("Cannot determine key/IV size for unknown mode.");
    }
    if (mode != ModeType::XTS && aesKeySize != 16 && aesKeySize != 24 && aesKeySize != 32)
    {
        throw std::runtime_error("Invalid AES key size specified (must be 16, 24, or 32).");
    }
    return {keySize, ivSize};
}

void generateKeyIV(SecByteBlock &key, SecByteBlock &iv, size_t keySize, size_t ivSize)
{
    AutoSeededRandomPool prng;
    key.resize(keySize);
    iv.resize(ivSize);
    prng.GenerateBlock(key, key.size());
    if (ivSize > 0)
    {
        prng.GenerateBlock(iv, iv.size());
    }
}

void saveKeyIVToFile(const char *filename, const SecByteBlock &key, const SecByteBlock &iv)
{
    if (!filename || strlen(filename) == 0)
    {
        throw std::runtime_error("Invalid filename provided for saving key/IV.");
    }
    try
    {
        FileSink file(filename);
        file.Put(key.BytePtr(), key.size());
        if (iv.size() > 0)
        {
            file.Put(iv.BytePtr(), iv.size());
        }
        std::cout << "Key and IV saved to file: " << filename << std::endl;
    }
    catch (const Exception &e)
    {
        throw std::runtime_error(std::string("Error saving key/IV to file (") + filename + "): " + e.what());
    }
}

size_t loadKeyIVFromFile(const char *filename, SecByteBlock &key, SecByteBlock &iv, size_t expectedKeySize)
{
    if (!filename || strlen(filename) == 0)
    {
        throw std::runtime_error("Invalid filename provided for loading key/IV.");
    }
    try
    {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file.is_open())
        {
            throw std::runtime_error(std::string("Cannot open key/IV file for reading: ") + filename);
        }
        std::streamsize fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        if (fileSize < (std::streamsize)expectedKeySize)
        {
            throw std::runtime_error(std::string("Key/IV file size is too small: ") + filename);
        }
        key.resize(expectedKeySize);
        if (!file.read(reinterpret_cast<char *>(key.BytePtr()), expectedKeySize))
        {
            throw std::runtime_error(std::string("Error reading key from file: ") + filename);
        }
        size_t actualIvSize = fileSize - expectedKeySize;
        if (actualIvSize > 0)
        {
            iv.resize(actualIvSize);
            if (!file.read(reinterpret_cast<char *>(iv.BytePtr()), actualIvSize))
            {
                throw std::runtime_error(std::string("Error reading IV/Nonce from file: ") + filename);
            }
        }
        else
        {
            iv.resize(0);
        }
        return actualIvSize;
    }
    catch (const Exception &e)
    {
        throw std::runtime_error(std::string("Error loading key/IV from file (") + filename + "): " + e.what());
    }
    catch (const std::ios_base::failure &e)
    {
        throw std::runtime_error(std::string("File I/O error loading key/IV (") + filename + "): " + e.what());
    }
    return 0;
}

bool LoadDataFromFile(const char *filename, std::vector<byte> &data)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
    {
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    if (!file.read(reinterpret_cast<char *>(data.data()), size))
    {
        return false;
    }
    return true;
}

void SaveDataToFile(const char *filename, const byte *data, size_t dataSize)
{
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file.is_open())
    {
        throw std::runtime_error(std::string("Cannot open output file for writing: ") + filename);
    }
    file.write(reinterpret_cast<const char *>(data), dataSize);
}

bool AESEncrypt(
    ModeType mode,
    const SecByteBlock &key,
    const SecByteBlock &iv,
    const byte *plaintext, size_t plaintextLen,
    byte *cipherBuffer, size_t *cipherLen // In/Out parameter
)
{
    if (!plaintext || !cipherBuffer || !cipherLen || *cipherLen == 0)
        return false;

    std::string ciphertext;
    try
    {
        switch (mode)
        {
        case ModeType::ECB:
        {
            ECB_Mode<AES>::Encryption encryptor(key, key.size());
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::CBC:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for CBC.");
            CBC_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::OFB:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for OFB.");
            OFB_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::CFB:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for CFB.");
            CFB_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::CTR:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for CTR.");
            CTR_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::XTS:
        {
            if (key.size() != 32 && key.size() != 48 && key.size() != 64)
                throw std::runtime_error("Invalid key size for XTS.");
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV (Tweak) size for XTS.");
            XTS_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext), StreamTransformationFilter::NO_PADDING));
            break;
        }
        case ModeType::CCM:
        {
            if (iv.size() < 7 || iv.size() > 13)
                throw std::runtime_error("Invalid Nonce size for CCM.");
            CCM<AES, CCM_TAG_SIZE>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            encryptor.SpecifyDataLengths(0, plaintextLen, 0);
            ArraySource(plaintext, plaintextLen, true, new AuthenticatedEncryptionFilter(encryptor, new StringSink(ciphertext), false, CCM_TAG_SIZE));
            break;
        }
        case ModeType::GCM:
        {
            GCM<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            ArraySource(plaintext, plaintextLen, true, new AuthenticatedEncryptionFilter(encryptor, new StringSink(ciphertext), false, GCM_TAG_SIZE));
            break;
        }
        default:
            throw std::runtime_error("Unsupported encryption mode");
        }

        if (ciphertext.size() > *cipherLen)
        {
            *cipherLen = ciphertext.size();
            return false;
        }
        memcpy(cipherBuffer, ciphertext.data(), ciphertext.size());
        *cipherLen = ciphertext.size();
        return true;
    }
    catch (const Exception &e)
    {
        // std::cerr << "Encryption error: " << e.what() << std::endl; // Optionally log
        *cipherLen = 0;
        return false;
    }
}

bool AESDecrypt(
    ModeType mode,
    const SecByteBlock &key,
    const SecByteBlock &iv,
    const byte *ciphertext, size_t cipherLen,
    byte *recoveredPlaintextBuffer, size_t *recoveredPlaintextLen // In/Out parameter
)
{
    if (!ciphertext || cipherLen == 0 || !recoveredPlaintextBuffer || !recoveredPlaintextLen || *recoveredPlaintextLen == 0)
        return false;

    std::string plaintext;
    try
    {
        switch (mode)
        {
        case ModeType::ECB:
        {
            ECB_Mode<AES>::Decryption decryptor(key, key.size());
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::CBC:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for CBC.");
            CBC_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::OFB:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for OFB.");
            OFB_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::CFB:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for CFB.");
            CFB_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::CTR:
        {
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV size for CTR.");
            CTR_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::XTS:
        {
            if (key.size() != 32 && key.size() != 48 && key.size() != 64)
                throw std::runtime_error("Invalid key size for XTS.");
            if (iv.size() != AES::BLOCKSIZE)
                throw std::runtime_error("Invalid IV (Tweak) size for XTS.");
            XTS_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext), StreamTransformationFilter::NO_PADDING));
            break;
        }
        case ModeType::CCM:
        {
            if (iv.size() < 7 || iv.size() > 13)
                throw std::runtime_error("Invalid Nonce size for CCM.");
            if (cipherLen < CCM_TAG_SIZE)
                throw std::runtime_error("Ciphertext too short for CCM tag.");
            CCM<AES, CCM_TAG_SIZE>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            decryptor.SpecifyDataLengths(0, cipherLen - CCM_TAG_SIZE, 0);
            AuthenticatedDecryptionFilter filter(decryptor, new StringSink(plaintext), AuthenticatedDecryptionFilter::THROW_EXCEPTION, CCM_TAG_SIZE);
            ArraySource(ciphertext, cipherLen, true, new Redirector(filter));
            break;
        }
        case ModeType::GCM:
        {
            if (cipherLen < GCM_TAG_SIZE)
                throw std::runtime_error("Ciphertext too short for GCM tag.");
            GCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            AuthenticatedDecryptionFilter filter(decryptor, new StringSink(plaintext), AuthenticatedDecryptionFilter::THROW_EXCEPTION, GCM_TAG_SIZE);
            ArraySource(ciphertext, cipherLen, true, new Redirector(filter));
            break;
        }
        default:
            throw std::runtime_error("Unsupported decryption mode");
        }

        if (plaintext.size() > *recoveredPlaintextLen)
        {
            *recoveredPlaintextLen = plaintext.size();
            return false;
        }
        memcpy(recoveredPlaintextBuffer, plaintext.data(), plaintext.size());
        *recoveredPlaintextLen = plaintext.size(); // Report actual size written
        return true;
    }
    catch (const Exception &e)
    {

        *recoveredPlaintextLen = 0;
        return false;
    }
}

void printUsage(const char *name)
{
    std::cerr << "Usage:\n"
              << "  " << name << " --generate --keysize <16|24|32> --keyfile <key_iv_output_file>\n"
              << "      Generates AES key of specified size and appropriate IV/Nonce, saves to file.\n\n"
              << "  " << name << " --encrypt --mode <MODE> --keyfile <key_iv_input_file> --input <plaintext_file> --output <ciphertext_file>\n"
              << "      Encrypts input file using specified mode and key/IV file (measures core crypto time).\n\n"
              << "  " << name << " --decrypt --mode <MODE> --keyfile <key_iv_input_file> --input <ciphertext_file> --output <recovered_plaintext_file>\n"
              << "      Decrypts input file using specified mode and key/IV file (measures core crypto time).\n\n"
              << "  " << name << " --help\n"
              << "      Displays this help message.\n\n"
              << "Supported Modes <MODE>: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM\n"
              << "Key Sizes: 16 (AES-128), 24 (AES-192), 32 (AES-256). XTS uses double this size in the key file.\n";
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printUsage(argv[0]);
        return 1;
    }

    OperationType operation = OperationType::UNKNOWN;
    ModeType mode = ModeType::UNKNOWN;
    size_t keySizeArg = 16;
    const char *keyFile = nullptr;
    const char *inputFile = nullptr;
    const char *outputFile = nullptr;

    try
    {
        operation = parseOperation(argv[1]);
        if (operation == OperationType::HELP || (argc == 2 && operation != OperationType::UNKNOWN))
        {
            printUsage(argv[0]);
            return (operation == OperationType::HELP) ? 0 : 1;
        }

        // Parse command line arguments
        for (int i = 2; i < argc; ++i)
        {
            const char *arg = argv[i];
            if (strcmp(arg, "--mode") == 0 && i + 1 < argc)
            {
                mode = parseMode(argv[++i]);
                if (mode == ModeType::UNKNOWN)
                    throw std::runtime_error(std::string("Invalid mode: ") + argv[i]);
            }
            else if (strcmp(arg, "--keysize") == 0 && i + 1 < argc)
            {
                try
                {
                    keySizeArg = std::stoi(argv[++i]);
                }
                catch (const std::invalid_argument &ia)
                {
                    throw std::runtime_error(std::string("Invalid keysize value: ") + argv[i]);
                }
                catch (const std::out_of_range &oor)
                {
                    throw std::runtime_error(std::string("Keysize value out of range: ") + argv[i]);
                }
                if (keySizeArg != 16 && keySizeArg != 24 && keySizeArg != 32)
                    throw std::runtime_error("Invalid keysize. Use 16, 24, or 32.");
            }
            else if (strcmp(arg, "--keyfile") == 0 && i + 1 < argc)
            {
                keyFile = argv[++i];
            }
            else if (strcmp(arg, "--input") == 0 && i + 1 < argc)
            {
                inputFile = argv[++i];
            }
            else if (strcmp(arg, "--output") == 0 && i + 1 < argc)
            {
                outputFile = argv[++i];
            }
            else if (operation == OperationType::GENERATE && keyFile == nullptr)
            {
                keyFile = arg;
            }
            else
            {
                throw std::runtime_error(std::string("Unknown or misplaced argument: ") + arg);
            }
        }

        switch (operation)
        {
        case OperationType::GENERATE:
        {
            if (keyFile == nullptr)
                throw std::runtime_error("Missing --keyfile argument for --generate.");

            SecByteBlock key, iv;
            std::pair<size_t, size_t> genSizes = GetKeyIVSize(parseMode("CBC"), keySizeArg); // Use CBC default for IV size determination
            if (parseMode("XTS") == mode)
            { // Adjust key size if XTS
                genSizes = GetKeyIVSize(mode, keySizeArg);
            }

            generateKeyIV(key, iv, genSizes.first, genSizes.second);
            saveKeyIVToFile(keyFile, key, iv); // Includes cout message
            break;
        }

        case OperationType::ENCRYPT:
        case OperationType::DECRYPT:
        {
            if (mode == ModeType::UNKNOWN)
                throw std::runtime_error("Missing or invalid --mode argument.");
            if (keyFile == nullptr)
                throw std::runtime_error("Missing --keyfile argument.");
            if (inputFile == nullptr)
                throw std::runtime_error("Missing --input argument.");
            if (outputFile == nullptr)
                throw std::runtime_error("Missing --output argument.");

            auto expectedSizes = GetKeyIVSize(mode, keySizeArg);
            SecByteBlock key, iv;
            size_t actualIvSize = loadKeyIVFromFile(keyFile, key, iv, expectedSizes.first);

            if (mode == ModeType::ECB && actualIvSize != 0)
            {
                std::cerr << "Warning: IV data found in keyfile but ECB mode does not use an IV." << std::endl;
            }
            else if (mode != ModeType::ECB && actualIvSize == 0)
            {
                throw std::runtime_error("IV/Nonce missing in keyfile for the selected mode.");
            }
            else if (mode == ModeType::XTS && actualIvSize != AES::BLOCKSIZE)
            {
                throw std::runtime_error(std::string("Invalid IV (Tweak) size in keyfile for XTS mode. Expected ") +
                                         std::to_string(AES::BLOCKSIZE) + " bytes, found " + std::to_string(actualIvSize) + " bytes.");
            }
            else if ((mode == ModeType::CBC || mode == ModeType::OFB ||
                      mode == ModeType::CFB || mode == ModeType::CTR) &&
                     actualIvSize != AES::BLOCKSIZE)
            {
                throw std::runtime_error(std::string("Invalid IV size in keyfile for selected mode. Expected ") +
                                         std::to_string(AES::BLOCKSIZE) + " bytes, found " + std::to_string(actualIvSize) + " bytes.");
            }
            else if (mode == ModeType::CCM && (actualIvSize < 7 || actualIvSize > 13))
            {
                throw std::runtime_error(std::string("Invalid Nonce size in keyfile for CCM mode. Expected 7-13 bytes, found ") +
                                         std::to_string(actualIvSize) + " bytes.");
            }

            std::cout << "Loading input file..." << std::endl;
            std::vector<byte> inputData;
            if (!LoadDataFromFile(inputFile, inputData))
            {
                throw std::runtime_error(std::string("Failed to load input file: ") + inputFile);
            }
            std::cout << "Input data size: " << inputData.size() << " bytes" << std::endl;

            size_t outputBufferSize = inputData.size() + AES::BLOCKSIZE + std::max(GCM_TAG_SIZE, CCM_TAG_SIZE);
            std::vector<byte> outputBuffer(outputBufferSize);
            size_t actualOutputSize = outputBufferSize; // Pass buffer size to function

            const int runs = 10000; // Keep timing for CLI
            bool success = false;
            double avgTime = 0.0;
            auto start = std::chrono::high_resolution_clock::now();

            if (operation == OperationType::ENCRYPT)
            {
                std::cout << "Starting encryption timing (" << runs << " rounds)..." << std::endl;
                for (int i = 0; i < runs; ++i)
                {
                    actualOutputSize = outputBufferSize;
                    success = AESEncrypt(mode, key, iv, inputData.data(), inputData.size(), outputBuffer.data(), &actualOutputSize);
                    if (!success && i == 0)
                    { // Check for buffer error on first run
                        if (actualOutputSize > outputBufferSize)
                        { // Buffer too small reported
                            outputBuffer.resize(actualOutputSize);
                            outputBufferSize = actualOutputSize;
                            success = AESEncrypt(mode, key, iv, inputData.data(), inputData.size(), outputBuffer.data(), &actualOutputSize);
                        }
                    }
                    if (!success)
                        break; // Stop timing if error occurs
                }
                auto end = std::chrono::high_resolution_clock::now();
                if (success)
                {
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    avgTime = static_cast<double>(duration) / runs;
                    std::cout << "Average encryption time: " << avgTime << " ms" << std::endl;
                }
                else
                {
                    throw std::runtime_error("Encryption failed during timing runs.");
                }
            }
            else // DECRYPT
            {
                std::cout << "Starting decryption timing (" << runs << " rounds)..." << std::endl;
                for (int i = 0; i < runs; ++i)
                {
                    actualOutputSize = outputBufferSize; // Reset buffer size input
                    success = AESDecrypt(mode, key, iv, inputData.data(), inputData.size(), outputBuffer.data(), &actualOutputSize);
                    if (!success && i == 0)
                    {
                        if (actualOutputSize > outputBufferSize)
                        {
                            outputBuffer.resize(actualOutputSize);
                            outputBufferSize = actualOutputSize;
                            success = AESDecrypt(mode, key, iv, inputData.data(), inputData.size(), outputBuffer.data(), &actualOutputSize);
                        }
                    }
                    if (!success)
                        break;
                }
                auto end = std::chrono::high_resolution_clock::now();
                if (success)
                {
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                    avgTime = static_cast<double>(duration) / runs;
                    std::cout << "Average decryption time: " << avgTime << " ms" << std::endl;
                }
                else
                {
                    throw std::runtime_error("Decryption failed during timing runs (check key/IV/mode/data integrity).");
                }
            }

            SaveDataToFile(outputFile, outputBuffer.data(), actualOutputSize);
            std::cout << "Output written to: " << outputFile << std::endl;
            break;
        }

        case OperationType::HELP:
            printUsage(argv[0]);
            break;

        default:
            throw std::runtime_error(std::string("Internal error: Invalid operation type."));
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
