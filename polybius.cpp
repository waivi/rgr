#define POLYBIUS_EXPORTS
#include "polybius.h"
#include <iostream>
#include <fstream>
#include <vector>
PolybiusSquare::PolybiusSquare() {
    for (int i = 0; i < 256; ++i) {
        unsigned char original_byte = static_cast<unsigned char>(i);
        unsigned char row = (original_byte >> 4) & 0x0F;
        unsigned char col = original_byte & 0x0F;
        unsigned char encrypted_repr = (col << 4) | row;
        encrypt_map_[original_byte] = encrypted_repr;
        decrypt_map_[encrypted_repr] = original_byte;
    }
}
bool PolybiusSquare::encrypt_file(const std::string& input_path, const std::string& output_path) const {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) { return false; }
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) { return false; }
    char byte;
    while (input_file.get(byte)) {
        unsigned char u_byte = static_cast<unsigned char>(byte);
        auto it = encrypt_map_.find(u_byte);
        if (it != encrypt_map_.end()) {
            output_file.put(static_cast<char>(it->second));
        } else {
            output_file.put(byte);
        }
    }
    return true;
}
bool PolybiusSquare::decrypt_file(const std::string& input_path, const std::string& output_path) const {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) { return false; }
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) { return false; }
    char byte;
    while (input_file.get(byte)) {
        unsigned char u_byte = static_cast<unsigned char>(byte);
        auto it = decrypt_map_.find(u_byte);
        if (it != decrypt_map_.end()) {
            output_file.put(static_cast<char>(it->second));
        } else {
            output_file.put(byte);
        }
    }
    return true;
}
std::vector<unsigned char> PolybiusSquare::encrypt_text(const std::string& plaintext) const {
    std::vector<unsigned char> ciphertext;
    ciphertext.reserve(plaintext.size());
    for (char c : plaintext) {
        unsigned char u_char = static_cast<unsigned char>(c);
        auto it = encrypt_map_.find(u_char);
        if (it != encrypt_map_.end()) {
            ciphertext.push_back(it->second);
        } else {
            ciphertext.push_back(u_char);
        }
    }
    return ciphertext;
}
std::string PolybiusSquare::decrypt_text(const std::vector<unsigned char>& ciphertext) const {
    std::string plaintext;
    plaintext.reserve(ciphertext.size());
    for (unsigned char byte : ciphertext) {
        auto it = decrypt_map_.find(byte);
        if (it != decrypt_map_.end()) {
            plaintext += static_cast<char>(it->second);
        } else {
            plaintext += static_cast<char>(byte);
        }
    }
    return plaintext;
}
