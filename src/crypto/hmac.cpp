#include "crypto.hpp"
#include <openssl/hmac.h>

void ::dsa::hmac::init(const char *alg, std::vector<byte> data) {
  const EVP_MD *md = EVP_get_digestbyname(alg);
  if (md == nullptr)
    throw std::runtime_error("Failed to initialize HMAC");

  HMAC_CTX_reset(ctx);
  
  if (!HMAC_Init_ex(ctx, &data[0], data.size(), md, nullptr))
    throw std::runtime_error("Failed to initialize HMAC");
}

dsa::hmac::hmac(const char *alg, std::vector<byte> data) {
  ctx = HMAC_CTX_new();
  init(alg, data);
  initialized = true;
}

dsa::hmac::~hmac() {
  HMAC_CTX_free(ctx);
}

void dsa::hmac::update(std::vector<byte> data) {
  if (!initialized)
    throw std::runtime_error("HMAC needs to be initialized");
  int r = HMAC_Update(ctx, &data[0], data.size());
  if (!r)
    throw std::runtime_error("Failed to update HMAC");
}

std::vector<byte> dsa::hmac::digest() {
  if (!initialized)
    throw std::runtime_error("HMAC needs to be initialized");

  byte md_value[EVP_MAX_MD_SIZE];
  uint md_len = 0;

  bool r = HMAC_Final(ctx, md_value, &md_len);
  if (!r)
    throw std::runtime_error("Failed to get digest");
  initialized = false;
  HMAC_CTX_reset(ctx);

  return std::vector<byte>(md_value, md_value + md_len);
}