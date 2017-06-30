#include "crypto.hpp"
#include <string>
#include <sstream>
#include <regex>
#include <iostream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

dsa::hash::hash(const char *hash_type) : finalized(false) {
  const EVP_MD *md = EVP_get_digestbyname(hash_type);
  if (md == nullptr)
    throw std::runtime_error("invalid hash type");
  mdctx = EVP_MD_CTX_create();
  EVP_MD_CTX_init(mdctx);
  if (EVP_DigestInit_ex(mdctx, md, nullptr) <= 0)
    throw std::runtime_error("something went wrong initializing digest");
}

dsa::hash::~hash() {
  EVP_MD_CTX_destroy(mdctx);
}

void dsa::hash::update(std::vector<byte> data) {
  EVP_DigestUpdate(mdctx, &data[0], data.size());
}

std::string dsa::hash::digest_base64() {
  if (finalized)
    throw std::runtime_error("digest already called");

  unsigned char *md_value = new unsigned char[EVP_MAX_MD_SIZE];
  unsigned int md_len;
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  finalized = true;

  std::string out = base64_encode(md_value, md_len);
  delete[] md_value;
  return out;
}

std::string dsa::gen_salt(int len) {
  unsigned char buf[len];
  if (!RAND_bytes(buf, len))
    throw std::runtime_error("Unable to generate salt");
  std::string out = reinterpret_cast<char *>(buf);
  out[len] = '\0';
  return out;
}

