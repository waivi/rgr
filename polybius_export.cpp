#define POLYBIUS_EXPORTS
#include "polybius.h"
#include <string>
#include <vector>
#include <cstring>
extern "C" {
    POLYBIUS_API bool encrypt_file_polybius(const char* input_path, const char* output_path) {
        PolybiusSquare cipher;
        return cipher.encrypt_file(input_path, output_path);
    }
    POLYBIUS_API bool decrypt_file_polybius(const char* input_path, const char* output_path) {
        PolybiusSquare cipher;
        return cipher.decrypt_file(input_path, output_path);
    }
    POLYBIUS_API std::vector<unsigned char>* encrypt_text_polybius(const char* text) {
        PolybiusSquare cipher;
        return new std::vector<unsigned char>(cipher.encrypt_text(text));
    }
    POLYBIUS_API char* decrypt_text_polybius(const unsigned char* data, size_t size) {
        PolybiusSquare cipher;
        std::vector<unsigned char> vec(data, data + size);
        std::string result = cipher.decrypt_text(vec);
        char* out = new char[result.length() + 1];
        #ifdef _WIN32
            strcpy_s(out, result.length() + 1, result.c_str());
        #else
            strcpy(out, result.c_str());
        #endif
        return out;
    }
    POLYBIUS_API void free_memory(void* ptr) {
        delete[] static_cast<char*>(ptr);
    }
    POLYBIUS_API void free_vector(void* ptr) {
        delete static_cast<std::vector<unsigned char>*>(ptr);
    }
}
