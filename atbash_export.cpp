#define ATBASH_EXPORTS
#include "atbash.h"
#include <string>
#include <locale>
#include <codecvt>
#include <cstring>

static std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

extern "C" {
    ATBASH_API char* process_text_atbash(const char* text) {
        AtbashCipher cipher;
        std::string input_str(text);
        std::wstring w_input = converter.from_bytes(input_str);
        std::wstring w_output = cipher.transform_text(w_input);
        std::string result = converter.to_bytes(w_output);
        
        char* out = new char[result.length() + 1];
        #ifdef _WIN32
            strcpy_s(out, result.length() + 1, result.c_str());
        #else
            strcpy(out, result.c_str());
        #endif
        return out;
    }
    
    ATBASH_API void process_file_atbash(const char* input_path, const char* output_path) {
        AtbashCipher cipher;
        cipher.transform_file(input_path, output_path);
    }

    ATBASH_API void free_memory_atbash(void* ptr) {
        delete[] static_cast<char*>(ptr);
    }
}
