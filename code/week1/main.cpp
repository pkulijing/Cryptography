#include <memory>
#include <cstdlib>
#include <glog/logging.h>
#include "decipher.h"

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  FLAGS_alsologtostderr = true;

  Decipher::space_xor_demo();

  if (argc < 3) {
    LOG(ERROR) << "usage: " << argv[0] << "[ciphertext file] [target file] [(optional)corretion file] [(optional)freq threshold]";
    return -1;
  }

  std::string ciphertext_file(argv[1]);
  std::string target_file(argv[2]);
  std::unique_ptr<Decipher> decipher;
  if (argc > 4) {
    int freq_threshold = std::atoi(argv[4]);
    decipher.reset(new Decipher(freq_threshold));
  } else {
    decipher.reset(new Decipher());
  }

  if (!decipher->init(ciphertext_file, target_file)) {
    LOG(ERROR) << "failed to init decipher with ciphertext file " << ciphertext_file
      << ", target file " << target_file;
    return -1;
  }

  if (argc > 3) {
    decipher->manual_correction(argv[3]);
  }

  std::stringstream indices;
  for (size_t i = 0; i < decipher->get_ciphered_target().length(); ++i) {
    indices << i % 10;
  }
  LOG(INFO) << "possible input msgs: (% represent uncertain character)";
  LOG(INFO) << indices.str();
  for (auto & text : decipher->get_ciphered_texts()) {
    LOG(INFO) << decipher->decipher_text(text);;
  }
  LOG(INFO) << "possible target msg: (% represent uncertain character)";
  LOG(INFO) << decipher->decipher_text(decipher->get_ciphered_target());
  return 0;
}
