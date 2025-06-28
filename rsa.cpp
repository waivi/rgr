#include "rsa.hpp"
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/integer/mod_inverse.hpp>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <sstream>

BigInt generate_probable_prime(unsigned int bits, boost::random::mt19937& rng) {
    BigInt n;
    boost::random::uniform_int_distribution<BigInt> dist(BigInt(1) << (bits - 1), (BigInt(1) << bits) - 1);
    do {
        n = dist(rng);
    } while (!boost::multiprecision::miller_rabin_test(n, 25, rng));
    return n;
}

RSAKeys generate_keys(unsigned int bits, boost::random::mt19937& rng) {
    if (bits < 512) throw std::runtime_error("Key size must be at least 512 bits.");
    unsigned int prime_bits = bits / 2;
    BigInt p = generate_probable_prime(prime_bits, rng);
    BigInt q;
    do {
        q = generate_probable_prime(prime_bits, rng);
    } while (p == q);
    BigInt n = p * q;
    BigInt phi_n = (p - 1) * (q - 1);
    BigInt e = 65537;
    BigInt d = boost::integer::mod_inverse(e, phi_n);
    return {n, e, d};
}

size_t get_byte_length(const BigInt& n) {
    return (n == 0) ? 1 : (static_cast<size_t>(msb(n)) + 8) / 8;
}

std::vector<unsigned char> big_int_to_bytes(const BigInt& val, size_t len) {
    std::vector<unsigned char> bytes;
    BigInt temp = val;
    while (temp > 0) {
        bytes.insert(bytes.begin(), static_cast<unsigned char>(temp & 0xFF));
        temp >>= 8;
    }
    if (bytes.size() < len) {
        bytes.insert(bytes.begin(), len - bytes.size(), 0);
    }
    return bytes;
}

BigInt bytes_to_big_int(const std::vector<unsigned char>& bytes) {
    BigInt res = 0;
    for (unsigned char byte : bytes) {
        res <<= 8;
        res |= byte;
    }
    return res;
}

std::vector<unsigned char> pkcs1_pad(const std::vector<unsigned char>& data_block, size_t n_len, boost::random::mt19937& rng) {
    if (n_len < data_block.size() + 11) throw std::runtime_error("Data block too large for key size.");
    std::vector<unsigned char> padded_block;
    padded_block.push_back(0x00);
    padded_block.push_back(0x02);
    size_t padding_len = n_len - 3 - data_block.size();
    boost::random::uniform_int_distribution<int> dist(1, 255);
    for (size_t i = 0; i < padding_len; ++i) {
        padded_block.push_back(dist(rng));
    }
    padded_block.push_back(0x00);
    padded_block.insert(padded_block.end(), data_block.begin(), data_block.end());
    return padded_block;
}

std::vector<unsigned char> pkcs1_unpad(const std::vector<unsigned char>& padded_block) {
    if (padded_block.size() < 11 || padded_block[0] != 0x00 || padded_block[1] != 0x02) {
         throw std::runtime_error("Decryption error: PKCS#1 padding format invalid.");
    }
    size_t separator_pos = 2;
    while (separator_pos < padded_block.size() && padded_block[separator_pos] != 0x00) {
        separator_pos++;
    }
    if (separator_pos == padded_block.size() || separator_pos < 10) {
        throw std::runtime_error("Decryption error: Padding separator not found or invalid.");
    }
    return std::vector<unsigned char>(padded_block.begin() + separator_pos + 1, padded_block.end());
}

bool encrypt_file(const std::string& input_path, const std::string& output_path, const RSAKeys& key, boost::random::mt19937& rng) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) return false;
    std::ofstream output_file(output_path);
    if (!output_file) return false;
    size_t n_len = get_byte_length(key.n);
    if (n_len < 12) return false;
    size_t data_chunk_size = n_len - 11;
    std::vector<unsigned char> buffer(data_chunk_size);
    while (input_file) {
        input_file.read(reinterpret_cast<char*>(buffer.data()), data_chunk_size);
        size_t bytes_read = input_file.gcount();
        if (bytes_read == 0) break;
        std::vector<unsigned char> data_block(buffer.begin(), buffer.begin() + bytes_read);
        std::vector<unsigned char> padded_block = pkcs1_pad(data_block, n_len, rng);
        BigInt m = bytes_to_big_int(padded_block);
        BigInt c = boost::multiprecision::powm(m, key.e, key.n);
        output_file << std::hex << c << std::endl;
    }
    return true;
}

bool decrypt_file(const std::string& input_path, const std::string& output_path, const RSAKeys& key) {
    std::ifstream input_file(input_path);
    if (!input_file) return false;
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) return false;
    size_t n_len = get_byte_length(key.n);
    std::string hex_c;
    while (input_file >> hex_c) {
        BigInt c(std::string("0x") + hex_c);
        BigInt m_padded = boost::multiprecision::powm(c, key.d, key.n);
        std::vector<unsigned char> padded_block = big_int_to_bytes(m_padded, n_len);
        std::vector<unsigned char> data_block = pkcs1_unpad(padded_block);
        output_file.write(reinterpret_cast<const char*>(data_block.data()), data_block.size());
    }
    return true;
}

std::string encrypt_text(const std::string& plaintext, const RSAKeys& key, boost::random::mt19937& rng) {
    std::vector<unsigned char> byte_vector(plaintext.begin(), plaintext.end());
    size_t n_len = get_byte_length(key.n);
    if (n_len < 12) throw std::runtime_error("Key too small.");
    size_t data_chunk_size = n_len - 11;
    std::stringstream result_stream;
    for (size_t i = 0; i < byte_vector.size(); i += data_chunk_size) {
        size_t end = std::min(i + data_chunk_size, byte_vector.size());
        std::vector<unsigned char> chunk(byte_vector.begin() + i, byte_vector.begin() + end);
        std::vector<unsigned char> padded_block = pkcs1_pad(chunk, n_len, rng);
        BigInt m = bytes_to_big_int(padded_block);
        BigInt c = boost::multiprecision::powm(m, key.e, key.n);
        result_stream << std::hex << c << (i + data_chunk_size < byte_vector.size() ? " " : "");
    }
    return result_stream.str();
}

std::string decrypt_text(const std::string& hex_ciphertext, const RSAKeys& key) {
    std::stringstream input_stream(hex_ciphertext);
    std::string hex_c;
    std::string decrypted_text;
    size_t n_len = get_byte_length(key.n);
    while (input_stream >> hex_c) {
        BigInt c(std::string("0x") + hex_c);
        BigInt m_padded = boost::multiprecision::powm(c, key.d, key.n);
        std::vector<unsigned char> padded_block = big_int_to_bytes(m_padded, n_len);
        std::vector<unsigned char> data_block = pkcs1_unpad(padded_block);
        decrypted_text.append(data_block.begin(), data_block.end());
    }
    return decrypted_text;
}

void save_key(const std::string& path, const BigInt& val1, const BigInt& val2) {
    std::ofstream file(path);
    if (file) {
        file << std::hex << val1 << std::endl;
        file << std::hex << val2 << std::endl;
    }
}

bool load_key(const std::string& path, BigInt& val1, BigInt& val2) {
    std::ifstream file(path);
    if (file) {
        std::string s1, s2;
        file >> s1 >> s2;
        if (file) {
            val1 = BigInt(std::string("0x") + s1);
            val2 = BigInt(std::string("0x") + s2);
            return true;
        }
    }
    return false;
}
