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
        // The key material size is double the AES key size
        if (aesKeySize == 16)
            keySize = 32;
        else if (aesKeySize == 24)
            keySize = 48;
        else if (aesKeySize == 32)
            keySize = 64;
        else
            throw std::runtime_error("Invalid AES key size specified for XTS (must be 16, 24, or 32).");
        ivSize = AES::BLOCKSIZE; // Tweak size
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
    // Validate base AES key size for non-XTS modes
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
            throw std::runtime_error(std::string("Key/IV file size is too small: ") + filename + ". Expected key size: " + std::to_string(expectedKeySize) + ", File size: " + std::to_string(fileSize));
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
        std::cerr << "Error: Cannot open input file: " << filename << std::endl;
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    if (!file.read(reinterpret_cast<char *>(data.data()), size))
    {
        std::cerr << "Error: Cannot read from input file: " << filename << std::endl;
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
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for CBC.");
            CBC_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::OFB:
        {
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for OFB.");
            OFB_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::CFB:
        {
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for CFB.");
            CFB_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::CTR:
        {
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for CTR.");
            CTR_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext)));
            break;
        }
        case ModeType::XTS:
        {
            // Key size check is now implicitly handled by GetKeyIVSize and loadKeyIVFromFile
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV (Tweak) size for XTS.");
            XTS_Mode<AES>::Encryption encryptor(key, key.size(), iv);
            ArraySource(plaintext, plaintextLen, true, new StreamTransformationFilter(encryptor, new StringSink(ciphertext), StreamTransformationFilter::NO_PADDING));
            break;
        }
        case ModeType::CCM:
        {
            // if (iv.size() < 7 || iv.size() > 13)
            //     throw std::runtime_error("Invalid Nonce size for CCM.");
            CCM<AES, CCM_TAG_SIZE>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
            encryptor.SpecifyDataLengths(0, plaintextLen, 0);
            ArraySource(plaintext, plaintextLen, true, new AuthenticatedEncryptionFilter(encryptor, new StringSink(ciphertext), false, CCM_TAG_SIZE));
            break;
        }
        case ModeType::GCM:
        {
            // if (iv.size() == 0) // GCM needs an IV
            //      throw std::runtime_error("Invalid IV size for GCM (cannot be 0).");
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
            *cipherLen = ciphertext.size(); // Report required size
            return false; // Indicate buffer too small
        }
        memcpy(cipherBuffer, ciphertext.data(), ciphertext.size());
        *cipherLen = ciphertext.size();
        return true;
    }
    catch (const Exception &e)
    {
        std::cerr << "Encryption error: " << e.what() << std::endl; // Log error
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
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for CBC.");
            CBC_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::OFB:
        {
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for OFB.");
            OFB_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::CFB:
        {
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for CFB.");
            CFB_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::CTR:
        {
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV size for CTR.");
            CTR_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext)));
            break;
        }
        case ModeType::XTS:
        {
            // Key size check is now implicitly handled by GetKeyIVSize and loadKeyIVFromFile
            // if (iv.size() != AES::BLOCKSIZE)
            //     throw std::runtime_error("Invalid IV (Tweak) size for XTS.");
            XTS_Mode<AES>::Decryption decryptor(key, key.size(), iv);
            ArraySource(ciphertext, cipherLen, true, new StreamTransformationFilter(decryptor, new StringSink(plaintext), StreamTransformationFilter::NO_PADDING));
            break;
        }
        case ModeType::CCM:
        {
            // if (iv.size() < 7 || iv.size() > 13)
            //     throw std::runtime_error("Invalid Nonce size for CCM.");
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
            //  if (iv.size() == 0) // GCM needs an IV
            //      throw std::runtime_error("Invalid IV size for GCM (cannot be 0).");
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
            *recoveredPlaintextLen = plaintext.size(); // Report required size
            return false; // Indicate buffer too small
        }
        memcpy(recoveredPlaintextBuffer, plaintext.data(), plaintext.size());
        *recoveredPlaintextLen = plaintext.size();
        return true;
    }
    catch (const InvalidCiphertext &e)
    {
        std::cerr << "Decryption error: Invalid ciphertext (authentication failed). " << e.what() << std::endl;
        *recoveredPlaintextLen = 0;
        return false;
    }
    catch (const Exception &e)
    {
        std::cerr << "Decryption error: " << e.what() << std::endl;
        *recoveredPlaintextLen = 0;
        return false;
    }
}

void printUsage(const char *appName)
{
    std::cerr << "Usage:\n"
              << "  " << appName << " --generate [--mode <MODE>] --keysize <16|24|32> --keyfile <key_iv_output_file>\n"
              << "      Generates AES key of specified size and appropriate IV/Nonce/Tweak, saves to file.\n"
              << "      Specify --mode XTS to generate correct key/tweak size for XTS.\n\n"
              << "  " << appName << " --encrypt --mode <MODE> --keyfile <key_iv_input_file> --input <plaintext_file> --output <ciphertext_file>\n"
              << "      Encrypts input file using specified mode and key/IV file.\n\n"
              << "  " << appName << " --decrypt --mode <MODE> --keyfile <key_iv_input_file> --input <ciphertext_file> --output <recovered_plaintext_file>\n"
              << "      Decrypts input file using specified mode and key/IV file.\n\n"
              << "  " << appName << " --help\n"
              << "      Displays this help message.\n\n"
              << "Supported Modes <MODE>: ECB, CBC, OFB, CFB, CTR, XTS, CCM, GCM\n"
              << "Key Sizes (--keysize): 16 (AES-128), 24 (AES-192), 32 (AES-256). This is the base AES key size.\n"
              << "Note: For XTS, the key material in the file will be double the specified --keysize.\n";
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
    // Optional: Set console code page for UTF-8 if needed on Windows
    // SetConsoleOutputCP(CP_UTF8);
    // SetConsoleCP(CP_UTF8);
#endif

    if (argc < 2)
    {
        printUsage(argv[0]);
        return 1;
    }

    OperationType operation = OperationType::UNKNOWN;
    ModeType mode = ModeType::UNKNOWN; // Default or determined later
    size_t keySizeArg = 16;            // Default AES key size
    const char *keyFile = nullptr;
    const char *inputFile = nullptr;
    const char *outputFile = nullptr;

    try
    {
        operation = parseOperation(argv[1]);

        if (operation == OperationType::HELP || (argc == 2 && operation != OperationType::UNKNOWN))
        {
            if (operation == OperationType::HELP || operation == OperationType::UNKNOWN)
            {
                printUsage(argv[0]);
                return (operation == OperationType::HELP) ? 0 : 1;
            }
        }

        // Parse arguments
        for (int i = 2; i < argc; ++i)
        {
            const char *arg = argv[i];
            if (strcmp(arg, "--mode") == 0 && i + 1 < argc)
            {
                mode = parseMode(argv[++i]);
                if (mode == ModeType::UNKNOWN)
                    throw std::runtime_error(std::string("Invalid mode specified: ") + argv[i]);
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
                // Allow any key size here as requested by user, validation happens later if needed
                // if (keySizeArg != 16 && keySizeArg != 24 && keySizeArg != 32)
                // {
                //     throw std::runtime_error("Invalid keysize specified. Use 16, 24, or 32.");
                // }
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
            else
            {
                // Allow positional keyfile for generate for backward compatibility?
                // if (operation == OperationType::GENERATE && keyFile == nullptr) {
                //     keyFile = arg;
                // } else {
                throw std::runtime_error(std::string("Unknown or misplaced argument: ") + arg);
                // }
            }
        }

        // Execute operation
        switch (operation)
        {
        case OperationType::GENERATE:
        {
            if (keyFile == nullptr)
                throw std::runtime_error("Missing --keyfile argument for --generate.");
            // Allow non-standard key sizes for generation if user intends
            // if (keySizeArg != 16 && keySizeArg != 24 && keySizeArg != 32)
            //      throw std::runtime_error("Invalid --keysize for generation (must be 16, 24, or 32).");

            // *** XTS FIX: Determine correct key/IV size based on mode ***
            size_t genKeySize = keySizeArg;
            size_t genIvSize = AES::BLOCKSIZE; // Default IV size

            // Use GetKeyIVSize to determine the actual sizes needed for the specified mode (or default if no mode given)
            // If no mode is specified for generate, assume a standard mode like CBC for IV size.
            ModeType genMode = (mode == ModeType::UNKNOWN) ? ModeType::CBC : mode; 
            
            // Special handling for XTS generation - needs standard AES key size input
            if (genMode == ModeType::XTS) {
                 if (keySizeArg != 16 && keySizeArg != 24 && keySizeArg != 32) {
                     throw std::runtime_error("For --generate with --mode XTS, --keysize must be the base AES key size (16, 24, or 32).");
                 }
                 std::pair<size_t, size_t> sizes = GetKeyIVSize(genMode, keySizeArg);
                 genKeySize = sizes.first; // Will be double the keySizeArg
                 genIvSize = sizes.second;
            } else {
                // For other modes, use the provided keysize directly (allowing non-standard)
                genKeySize = keySizeArg;
                // Determine IV size based on mode (or default to block size)
                 try {
                     std::pair<size_t, size_t> sizes = GetKeyIVSize(genMode, keySizeArg);
                     // We only care about IV size here, key size is taken directly from arg
                     genIvSize = sizes.second;
                 } catch (const std::runtime_error&) {
                     // If GetKeyIVSize fails (e.g., non-standard key size for a mode that checks),
                     // default to block size IV. User is responsible for consequences.
                     genIvSize = AES::BLOCKSIZE;
                     std::cerr << "Warning: Could not determine standard IV size for mode/keysize combination. Defaulting IV size to " << AES::BLOCKSIZE << " bytes." << std::endl;
                 }
            }

            std::cout << "Generating key/IV..." << std::endl;
            std::cout << "  Key material size: " << genKeySize << " bytes" << std::endl;
            std::cout << "  IV/Nonce/Tweak size: " << genIvSize << " bytes" << std::endl;

            SecByteBlock key, iv;
            generateKeyIV(key, iv, genKeySize, genIvSize);
            saveKeyIVToFile(keyFile, key, iv);
        }
        break;

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

            // Determine expected key/IV sizes for the specified mode
            // We need the *base* AES key size (keySizeArg) to call GetKeyIVSize
            size_t baseAesKeySize = keySizeArg; // Assume user provides base size
            size_t expectedKeySize = baseAesKeySize;
            size_t expectedIvSize = AES::BLOCKSIZE;
            try {
                 std::pair<size_t, size_t> expectedSizes = GetKeyIVSize(mode, baseAesKeySize);
                 expectedKeySize = expectedSizes.first; // This is the size to read from file (e.g., double for XTS)
                 expectedIvSize = expectedSizes.second;
            } catch (const std::runtime_error& e) {
                 // Allow proceeding if GetKeyIVSize fails due to non-standard base key size
                 std::cerr << "Warning: Could not determine standard key/IV sizes for mode/keysize combination. Proceeding with provided keysize. Error: " << e.what() << std::endl;
                 // For XTS, we still need to calculate the expected double key size manually
                 if (mode == ModeType::XTS) {
                     expectedKeySize = baseAesKeySize * 2;
                 } else {
                     expectedKeySize = baseAesKeySize;
                 }
                 // Assume block size IV if mode expects one, otherwise 0
                 expectedIvSize = (mode == ModeType::ECB) ? 0 : AES::BLOCKSIZE;
                 std::cerr << "Assuming expected key file size: " << expectedKeySize << " bytes, IV size: " << expectedIvSize << " bytes." << std::endl;
            }

            // Load Key/IV
            SecByteBlock key, iv;
            // size_t actualIvSize = loadKeyIVFromFile(keyFile, key, iv, expectedKeySize);
            std::cout << "Key (" << key.size() << " bytes) and IV/Nonce/Tweak (" << iv.size() << " bytes) loaded from: " << keyFile << std::endl;

            // Validate IV size strictly based on mode requirements (using expectedIvSize calculated above)
            // Commented out as per user request
            // if (expectedIvSize > 0 && actualIvSize != expectedIvSize) {
            //      throw std::runtime_error("IV/Nonce/Tweak size mismatch in keyfile '" + std::string(keyFile) +
            //                              "'. Expected " + std::to_string(expectedIvSize) + " bytes for mode, found " + std::to_string(actualIvSize) + " bytes.");
            // } else if (expectedIvSize == 0 && actualIvSize != 0) {
            //      std::cerr << "Warning: IV data found in keyfile but mode does not use an IV." << std::endl;
            // }

            // Load input data
            std::cout << "Loading input file..." << std::endl;
            std::vector<byte> inputData;
            if (!LoadDataFromFile(inputFile, inputData))
            {
                throw std::runtime_error(std::string("Failed to load input file: ") + inputFile);
            }
            std::cout << "Input data size: " << inputData.size() << " bytes" << std::endl;

            // Prepare output buffer (estimate size)
            size_t outputBufferSize = inputData.size() + AES::BLOCKSIZE + GCM_TAG_SIZE; // Generous estimate
            std::vector<byte> outputData(outputBufferSize);
            size_t actualOutputSize = outputBufferSize;

            // Perform Encryption/Decryption
            bool success = false;
            double averageTime = 0.0;
            const int runs = 10000; // Number of runs for timing

            if (operation == OperationType::ENCRYPT)
            {
                std::cout << "Starting encryption timing (" << runs << " rounds)..." << std::endl;
                auto start = std::chrono::high_resolution_clock::now();
                for (int i = 0; i < runs; ++i)
                {
                    actualOutputSize = outputBufferSize; // Reset size for each run
                    success = AESEncrypt(mode, key, iv, inputData.data(), inputData.size(), outputData.data(), &actualOutputSize);
                    if (!success && actualOutputSize > outputBufferSize) { // Check if buffer was too small
                         throw std::runtime_error("Internal error: Initial output buffer too small during timing.");
                    }
                     if (!success) { // Handle other crypto errors during timing
                         throw std::runtime_error("Encryption failed during timing loop.");
                    }
                }
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                averageTime = static_cast<double>(duration) / runs;
                std::cout << "Average encryption time: " << averageTime << " ms" << std::endl;
            }
            else // DECRYPT
            {
                std::cout << "Starting decryption timing (" << runs << " rounds)..." << std::endl;
                auto start = std::chrono::high_resolution_clock::now();
                for (int i = 0; i < runs; ++i)
                {
                    actualOutputSize = outputBufferSize; // Reset size
                    success = AESDecrypt(mode, key, iv, inputData.data(), inputData.size(), outputData.data(), &actualOutputSize);
                     if (!success && actualOutputSize > outputBufferSize) {
                         throw std::runtime_error("Internal error: Initial output buffer too small during timing.");
                    }
                     if (!success) {
                         throw std::runtime_error("Decryption failed during timing loop (check key/IV/ciphertext/tag).");
                    }
                }
                auto end = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
                averageTime = static_cast<double>(duration) / runs;
                std::cout << "Average decryption time: " << averageTime << " ms" << std::endl;
            }

            // Save the result of the *last* operation (timing loop overwrites)
            if (success)
            {
                SaveDataToFile(outputFile, outputData.data(), actualOutputSize);
                std::cout << "Output written to: " << outputFile << std::endl;
            }
            else
            {
                std::cerr << "Operation failed after timing loop. Output file not written." << std::endl;
                return 1; 
            }
        }
        break;

        case OperationType::HELP:
            printUsage(argv[0]);
            break;

        case OperationType::UNKNOWN:
        default:
            std::string unknownOp = (argc > 1 && argv[1]) ? std::string(argv[1]) : "<unknown>";
            throw std::runtime_error(std::string("Invalid operation specified: ") + unknownOp);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        // printUsage(argv[0]); // Usage might be redundant if error is specific
        return 1;
    }

    return 0;
}

