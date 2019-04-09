#ifndef DECIPHER_H_
#define DECIPHER_H_
#include <string>
#include <vector>
#include <unordered_set>
class Decipher {
public:
  Decipher(int threshold = 5) : freq_threshold_(threshold) {}  
  bool init(const std::string& cipher_texts_file,
    const std::string& target_file);
  
  std::vector<std::string> get_ciphered_texts() const;
  std::string get_ciphered_target() const;

  std::string get_key() const;
  std::string decipher_text(const std::string& ciphered) const;

  void manual_correction(const std::string& correction_file);

  static void space_xor_demo();
private:
  
  static char literal2hex_(char c);
  static char hex2literal_(char c);
  static char two_literal_to_hex_byte_(char a, char b);
  static std::string literal_str_2_hex_byte_str_(const std::string& literal_str);
  static std::string hex_byte_str_xor_(const std::string& a, const std::string& b);

  std::vector<std::vector<int>> calc_freqs_(
    const std::vector<std::string>& ciphered_texts,
    size_t len);

  std::vector<std::string> ciphered_texts_;
  std::string ciphered_target_;

  std::vector<std::string> deciphered_texts_;
  std::string deciphered_target_;

  std::string key_;
  std::unordered_set<size_t> uncertain_digits_;
  int freq_threshold_;
};
#endif // DECIPHER_H_