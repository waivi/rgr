#ifndef ATBASH_H
#define ATBASH_H
#include <string>
#if defined(_WIN32)
    #ifdef ATBASH_EXPORTS
        #define ATBASH_API __declspec(dllexport)
    #else
        #define ATBASH_API __declspec(dllimport)
    #endif
#else
    #define ATBASH_API
#endif
class ATBASH_API AtbashCipher {
public:
    std::wstring transform_text(const std::wstring& w_text) const;
    void transform_file(const std::string& input_path, const std::string& output_path) const;
};
#endif // ATBASH_H
