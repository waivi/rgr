#ifndef POLYBIUS_H
#define POLYBIUS_H
#include <string>
#include <vector>
#include <map>
#if defined(_WIN32)
    #ifdef POLYBIUS_EXPORTS
        #define POLYBIUS_API __declspec(dllexport)
    #else
        #define POLYBIUS_API __declspec(dllimport)
    #endif
#else
    #define POLYBIUS_API
#endif
class POLYBIUS_API PolybiusSquare {
public:
    PolybiusSquare();
    bool encrypt_file(const std::string &input_path, const std::string &output_path) const;
    bool decrypt_file(const std::string &input_path, const std::string &output_path) const;
    std::vector<unsigned char> encrypt_text(const std::string &plaintext) const;
    std::string decrypt_text(const std::vector<unsigned char> &ciphertext) const;
private:
    std::map<unsigned char, unsigned char> encrypt_map_;
    std::map<unsigned char, unsigned char> decrypt_map_;
};
#endif // POLYBIUS_H
