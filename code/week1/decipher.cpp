#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <glog/logging.h>
#include "decipher.h"

void Decipher::space_xor_demo() {
  char space = ' ';
  std::stringstream ssm;
  ssm << "after xor with space: ";
  for (char c = 'a'; c <= 'z'; ++c) {
    ssm << c << "->" << (char)(c ^ space) << " ";
  }
  for (char c = 'A'; c <= 'Z'; ++c) {
    ssm << c << "->" << (char)(c ^ space) << " ";
  }
  LOG(INFO) << ssm.str();
}
// '2'->2 'a'->10
char Decipher::literal2hex_(char c) {
  if (!isxdigit(c)) {
    throw std::invalid_argument("literal2hex " + std::to_string((int)c) 
      + " does not represent a hex digit");
  }
  if (isdigit(c)) {
    return c - '0';
  }
  if (isupper(c)) {
    return c - 'A' + 10;
  }
  return c - 'a' + 10;
}

// 2->'2', 10->'a'
char Decipher::hex2literal_(char c) {
  if (c > 15 || c < 0) {
    throw std::invalid_argument("hex2literal " + std::to_string((int)c) + " is not a hex digit");
  }
  if (c < 10) {
    return c + '0';
  }
  return c - 10 + 'a';
}

char Decipher::two_literal_to_hex_byte_(char a, char b) {
  return (literal2hex_(a) << 4) + literal2hex_(b);
}

std::string Decipher::literal_str_2_hex_byte_str_(const std::string& literal_str) {
  if (literal_str.length() % 2 != 0) {
    throw std::invalid_argument("str length should be even");
  }    
  size_t len = literal_str.length();
  std::string res;
  for (size_t i = 0; i < len; i += 2) {
    res.push_back(two_literal_to_hex_byte_(literal_str[i], literal_str[i + 1]));
  }
  return res;
}

std::string Decipher::hex_byte_str_xor_(const std::string& a, const std::string& b) {
  std::string res;
  size_t len = std::min(a.length(), b.length());
  for (size_t i = 0; i < len; ++i) {
    res.push_back(a[i] ^ b[i]);
  }
  return res;
}

std::string Decipher::get_key() const {
  return key_;
}

std::vector<std::string> Decipher::get_ciphered_texts() const {
  return ciphered_texts_;
}

std::string Decipher::get_ciphered_target() const {
  return ciphered_target_;
}

std::string Decipher::decipher_text(const std::string& ciphered) const {
  std::string res = hex_byte_str_xor_(key_, ciphered);
  for (auto& d : uncertain_digits_) {
    res[d] = '%';
  }
  return res;
}

bool Decipher::init(const std::string& cipher_texts_file,
  const std::string& target_file) {
  std::fstream cipher_texts_fs(cipher_texts_file);
  std::fstream target_fs(target_file);
  
  std::string line;
  while (std::getline(cipher_texts_fs, line)) {
    LOG(INFO) << "get cipher text " << ciphered_texts_.size() << ": " << line;
    ciphered_texts_.push_back(literal_str_2_hex_byte_str_(line));
  }
  if (std::getline(target_fs, line)) {
    LOG(INFO) << "get target text :" << line;
    ciphered_target_ = literal_str_2_hex_byte_str_(line);
  }

  if (ciphered_texts_.empty() || ciphered_target_.empty()) {
    LOG(ERROR) << "Something is wrong. Did you use the correct file names?";
    return false;
  }

  auto freq = calc_freqs_(ciphered_texts_, ciphered_target_.size());

  for (size_t k = 0; k < ciphered_target_.size(); ++k) {
    auto it = std::max_element(freq[k].begin(), freq[k].end());
    if (*it < freq_threshold_) {
      LOG(INFO) << "position " << k << " of key is uncertain (freq = " << *it << ")";
      uncertain_digits_.insert(k);
      key_.push_back(0);
    } else {
      auto pos = it - freq[k].begin();
      LOG(INFO) << "position " << k << " of ciphertext " << pos << " is possibly space"
        " (freq = " << *it << ")";
      key_.push_back(ciphered_texts_[pos][k] ^ ' ');
    }
  }

  return true;
}

void Decipher::manual_correction(const std::string& correction_file) {
  std::fstream correction_fs(correction_file);
  if (correction_fs) {
    std::string line;
    while (std::getline(correction_fs, line)) {
      std::stringstream ssm(line);
      int msg_id, pos;
      char val;
      if (ssm >> msg_id >> pos >> val) {
        LOG(INFO) << "manual correction: msg " << msg_id << ", pos " << pos 
          << ", val " << val;
        key_[pos] = ciphered_texts_[msg_id][pos] ^ val;
        uncertain_digits_.erase(pos);
      }
    }
  }  
}

std::vector<std::vector<int>> Decipher::calc_freqs_(
  const std::vector<std::string>& ciphered_texts, size_t len) {
  auto num_ciphered = ciphered_texts.size();
  std::vector<std::vector<int>> freq(len, std::vector<int>(num_ciphered, 0));
  for (size_t i = 0; i < num_ciphered; ++i) {
    for (size_t j = i + 1; j < num_ciphered; ++j) {
      std::string xorij = hex_byte_str_xor_(ciphered_texts[i], ciphered_texts[j]);
      size_t stat_len = std::min(len, xorij.length());
      for (size_t k = 0; k < stat_len; ++k) {
        if (isalpha(xorij[k])) {
          ++freq[k][i];
          ++freq[k][j];
        }
      }
    }
  }
  return freq;
}
