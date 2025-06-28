#ifndef RSA_HPP
#define RSA_HPP
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
using BigInt = boost::multiprecision::cpp_int;
struct RSAKeys {
    BigInt n, e, d;
};
RSAKeys generate_keys(unsigned int bits, boost::random::mt19937& rng);
bool encrypt_file(const std::string& input_path, const std::string& output_path, const RSAKeys& key, boost::random::mt19937& rng);
bool decrypt_file(const std::string& input_path, const std::string& output_path, const RSAKeys& key);
std::string encrypt_text(const std::string& plaintext, const RSAKeys& key, boost::random::mt19937& rng);
std::string decrypt_text(const std::string& hex_ciphertext, const RSAKeys& key);
void save_key(const std::string& path, const BigInt& val1, const BigInt& val2);
bool load_key(const std::string& path, BigInt& val1, BigInt& val2);
#endif // RSA_HPP
