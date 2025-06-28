#include "rsa.hpp"
#include <string>
#include <vector>
#include <sstream>
#include <cstring>
#include <ctime>
#include <iostream>

#if defined(_WIN32)
    #define RSA_API __declspec(dllexport)
#else
    #define RSA_API
#endif

char* copy_string_to_char_ptr(const std::string& s) {
    char* ptr = new char[s.length() + 1];
    #ifdef _WIN32
        strcpy_s(ptr, s.length() + 1, s.c_str());
    #else
        strcpy(ptr, s.c_str());
    #endif
    return ptr;
}

extern "C" {
    RSA_API bool generate_and_save_keys(unsigned int bits, const char* pub_path, const char* priv_path) {
        try {
            boost::random::mt19937 rng(static_cast<unsigned int>(std::time(0)));
            RSAKeys keys = generate_keys(bits, rng);
            save_key(pub_path, keys.n, keys.e);
            save_key(priv_path, keys.n, keys.d);
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error during key generation: " << e.what() << std::endl;
            return false;
        }
    }

    RSA_API bool encrypt_file_wrapper(const char* pub_key_path, const char* input_file, const char* output_file) {
        try {
            RSAKeys key;
            if (!load_key(pub_key_path, key.n, key.e)) { return false; }
            boost::random::mt19937 rng(static_cast<unsigned int>(std::time(0)));
            return encrypt_file(input_file, output_file, key, rng);
        } catch (const std::exception& e) {
            std::cerr << "Error during file encryption: " << e.what() << std::endl;
            return false;
        }
    }

    RSA_API bool decrypt_file_wrapper(const char* priv_key_path, const char* input_file, const char* output_file) {
        try {
            RSAKeys key;
            if (!load_key(priv_key_path, key.n, key.d)) { return false; }
            return decrypt_file(input_file, output_file, key);
        } catch (const std::exception& e) {
            std::cerr << "Error during file decryption: " << e.what() << std::endl;
            return false;
        }
    }

    RSA_API char* encrypt_text_wrapper(const char* pub_key_path, const char* plaintext) {
        try {
            RSAKeys key;
            if (!load_key(pub_key_path, key.n, key.e)) { return nullptr; }
            boost::random::mt19937 rng(static_cast<unsigned int>(std::time(0)));
            std::string result = encrypt_text(plaintext, key, rng);
            return copy_string_to_char_ptr(result);
        } catch (const std::exception& e) {
            std::cerr << "Error during text encryption: " << e.what() << std::endl;
            return nullptr;
        }
    }

    RSA_API char* decrypt_text_wrapper(const char* priv_key_path, const char* ciphertext_hex) {
         try {
            RSAKeys key;
            if (!load_key(priv_key_path, key.n, key.d)) { return nullptr; }
            std::string result = decrypt_text(ciphertext_hex, key);
            return copy_string_to_char_ptr(result);
        } catch (const std::exception& e) {
            std::cerr << "Error during text decryption: " << e.what() << std::endl;
            return nullptr;
        }
    }

    RSA_API void free_rsa_string(char* str) {
        delete[] str;
    }
}
