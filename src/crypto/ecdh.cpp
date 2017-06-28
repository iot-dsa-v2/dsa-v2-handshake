#include "crypto.hpp"
#include <string>
#include <vector>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/bn.h>

template <typename T, typename U>
inline void CHECK_NE(T a, U b) {
  if (a == b)
    throw ("Something went wrong, can't be equal.");
}

dsa::ecdh::ecdh(const char *curve) {
  int nid = OBJ_sn2nid(curve);
  if (nid == NID_undef)
    throw ("invalid curve name");
  key = EC_KEY_new_by_curve_name(nid);
  if (!EC_KEY_generate_key(key))
    throw ("failed to generate ecdh key");
  group = EC_KEY_get0_group(key);
}

dsa::ecdh::~ecdh() {
  EC_KEY_free(key);
}

std::string dsa::ecdh::get_private_key() {
  const BIGNUM *priv = EC_KEY_get0_private_key(key);
  if (priv == nullptr)
    throw("private key not set");
  std::string out = BN_bn2hex(priv);
  return out + '\0';
}

std::string dsa::ecdh::get_public_key() {
  const EC_POINT *pub = EC_KEY_get0_public_key(key);
  if (pub == nullptr)
    throw("public key not set");
  int size = public_key_length();
  unsigned char data[size + 1];
  point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
  EC_POINT_point2oct(group, pub, form, data, size, nullptr);
  data[size] = '\0';
  return reinterpret_cast<char *>(data);
}

int dsa::ecdh::private_key_length() {
  const BIGNUM *priv = EC_KEY_get0_private_key(key);
  if (priv == nullptr)
    throw("private key not set");
  return (int)BN_num_bytes(priv);
}

int dsa::ecdh::public_key_length() {
  const EC_POINT *pub = EC_KEY_get0_public_key(key);
  if (pub == nullptr)
    throw("public key not set");
  point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
  int size = EC_POINT_point2oct(group, pub, form, nullptr, 0, nullptr);
  if (size == 0)
    throw("unable to get public key length");
  return size;
}

bool dsa::ecdh::is_key_valid_for_curve(BIGNUM *private_key) {
  if (group == nullptr)
    throw("group cannot be null");
  if (private_key == nullptr)
    throw("private key cannot be null");
  if (BN_cmp(private_key, BN_value_one()) < 0)
    return false;

  BIGNUM *order = BN_new();
  if (order == nullptr)
    throw("something went wrong, order can't be null");
  bool result = EC_GROUP_get_order(group, order, nullptr) &&
                BN_cmp(private_key, order) < 0;
  BN_free(order);
  return result;
}

void dsa::ecdh::set_private_key_hex(const char *data) {
  BIGNUM *priv = BN_new();
  int size = BN_hex2bn(&priv, data);
  if (!is_key_valid_for_curve(priv))
    throw("invalid key for curve");
  
  int result = EC_KEY_set_private_key(key, priv);
  BN_free(priv);

  if (!result)
    throw("failed to convert BN to private key");
  
  // To avoid inconsistency, clear the current public key in-case computing
  // the new one fails for some reason.
  EC_KEY_set_public_key(key, nullptr);

  const BIGNUM *priv_key = EC_KEY_get0_private_key(key);
  CHECK_NE(priv_key, nullptr);

  EC_POINT *pub = EC_POINT_new(group);
  CHECK_NE(pub, nullptr);

  if (!EC_POINT_mul(group, pub, priv_key, nullptr, nullptr, nullptr)) {
    EC_POINT_free(pub);
    throw("Failed to generate ecdh public key");
  } 

  if (!EC_KEY_set_public_key(key, pub)) {
    EC_POINT_free(pub);
    return throw("Failed to set generated public key");
  }

  EC_POINT_free(pub);
}

