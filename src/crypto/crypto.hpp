#ifndef DSA_CRYPTO_HPP
#define DSA_CRYPTO_HPP

#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/evp.h>

typedef unsigned char byte;

namespace dsa {
  class ecdh {
  private:
    EC_KEY *key;
    const EC_GROUP *group;
    bool is_key_valid_for_curve(BIGNUM *private_key);

  public:
    ecdh(const char *curve);
    ~ecdh();
    
    std::string get_private_key();
    std::string get_public_key();
    int private_key_length();
    int public_key_length();
    void set_private_key_hex(const char *data);
  };

  class hash {
  private:
    EVP_MD_CTX *mdctx;
    bool finalized;

  public:
    hash(const char *hash_type);
    ~hash();

    void update(std::string data);
    std::string digest_base64();
  };

  std::string base64url(std::string str);
  std::string base64_decode(std::string const& encoded_string);
  std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
  std::string gen_salt(int len);
  std::vector<unsigned char> hex2bin(const char *src);
}

#endif // DSA_CRYPTO_HPP