#include "client.hpp"
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <cstring>
#include <string>
#include <vector>

#include "crypto.hpp"

#define END_IF(X)                                                              \
  if (X) {                                                                     \
    ss << "fail" << std::endl;                                                 \
    std::cout << ss.str();                                                     \
    return;                                                                    \
  }

#ifndef USE_SSL // don't USE_SSL

client::client(boost::shared_ptr<boost::asio::io_service> io_service,
               char *host, int port)
    : sock(*io_service), strand(*io_service), ecdh("secp256k1") {

#else // USE_SSL

client::client(boost::shared_ptr<boost::asio::io_service> io_service,
               char *host, int port, boost::asio::ssl::context &context)
    : sock(*io_service, context), strand(*io_service), ecdh("secp256k1") {
  sock.set_verify_mode(boost::asio::ssl::verify_peer);
  sock.set_verify_callback(
      boost::bind(&client::verify_certificate, this, _1, _2));

#endif // USE_SSL

  token = "sample_token_string";

  dsa::hash hash("sha256");
  public_key = ecdh.get_public_key();
  hash.update(public_key);
  dsid = "mlink-" + dsa::base64url(hash.digest_base64());

  salt = dsa::gen_salt(32);

  boost::asio::ip::tcp::resolver resolver(*io_service);
  boost::asio::ip::tcp::resolver::query query(
      host, boost::lexical_cast<std::string>(port));
  boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

#ifndef USE_SSL // don't USE_SSL
  boost::asio::ip::tcp::endpoint endpoint = *iterator;

  sock.async_connect(endpoint, boost::bind(&client::start_handshake, this,
                                           boost::asio::placeholders::error));
#else  // USE_SSL
  boost::asio::async_connect(sock.lowest_layer(), iterator,
                             boost::bind(&client::handle_ssl_handshake, this,
                                         boost::asio::placeholders::error));
#endif // USE_SSL
}

#ifdef USE_SSL
bool client::verify_certificate(bool preverified,
                                boost::asio::ssl::verify_context &ctx) {
  // The verify callback can be used to check whether the certificate that is
  // being presented is valid for the peer. For example, RFC 2818 describes
  // the steps involved in doing this for HTTPS. Consult the OpenSSL
  // documentation for more details. Note that the callback is called once
  // for each certificate in the certificate chain, starting from the root
  // certificate authority.

  // In this example we will simply print the certificate's subject name.
  char subject_name[256];
  X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
  X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
  std::stringstream ss;
  ss << "Verifying " << subject_name << std::endl << std::endl;
  std::cout << ss.str();

  return preverified;
}

void client::handle_ssl_handshake(const boost::system::error_code &err) {
  if (!err) {
    sock.async_handshake(boost::asio::ssl::stream_base::client,
        boost::bind(&client::start_handshake, this, boost::asio::placeholders::error));
  } else {
    std::stringstream ss;
    ss << "Error: " << err << std::endl;
    std::cout << ss.str();
  }
}
#endif // USE_SSL

void client::start_handshake(const boost::system::error_code &err) {
  if (err) {
    std::stringstream ss;
    ss << "[client::start_handshake] Error: " << err << std::endl;
    std::cerr << ss.str();
  } else {
    int size = load_f0();
    boost::asio::async_write(
        sock, boost::asio::buffer(write_buf, size),
        boost::bind(&client::f0_sent, this, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void checking(std::stringstream &ss, const char *message, bool saving = false) {
  ss << (saving ? "saving " : "checking ");
  int i = 0;
  while (message[i] != '\0')
    ss << message[i++];
  while ((saving ? 7 : 9) + (i++) < 30)
    ss << '.';
}

void client::f0_sent(const boost::system::error_code &err,
                     size_t bytes_transferred) {
  if (err) {
    std::stringstream ss;
    ss << "[clien::f0_sent] Error: " << err << std::endl;
    std::cerr << ss.str();
  } else {
    std::stringstream ss;
    std::cout << "f0 sent, " << bytes_transferred << " bytes transferred"
              << std::endl;
    std::cout << ss.str();
    sock.async_read_some(
        boost::asio::buffer(read_buf, max_length),
        boost::bind(&client::f1_received, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void client::f1_received(const boost::system::error_code &err,
                         size_t bytes_transferred) {
  if (err) {
    std::stringstream ss;
    ss << "[client::f1_received] Error: " << err << std::endl;
    std::cerr << ss.str();
  } else {
    std::stringstream ss;
    std::cout << std::endl;
    std::cout << "f1 received, " << bytes_transferred << " bytes transferred"
              << std::endl;

    byte *cur = read_buf;

    /* check to make sure message size matches */
    checking(ss, "message size");
    uint32_t message_size;
    std::memcpy(&message_size, cur, sizeof(message_size));
    END_IF(message_size != bytes_transferred);
    cur += sizeof(message_size);
    ss << message_size << std::endl;

    /* check to make sure header length is correct */
    checking(ss, "header length");
    uint16_t header_size;
    std::memcpy(&header_size, cur, sizeof(header_size));
    END_IF(header_size != 11);
    cur += sizeof(header_size);
    ss << header_size << std::endl;

    /* check to make sure message type is correct */
    checking(ss, "message type");
    byte message_type;
    std::memcpy(&message_type, cur, sizeof(message_type));
    END_IF(message_type != 0xf1);
    cur += 1;
    ss << std::hex << (uint)message_type << std::dec << std::endl;

    /* check to make sure request id is correct */
    checking(ss, "request id");
    uint32_t request_id;
    std::memcpy(&request_id, cur, sizeof(request_id));
    END_IF(request_id != 0);
    cur += sizeof(request_id);
    ss << request_id << std::endl;

    /* check DSID length */
    checking(ss, "DSID length");
    byte dsid_length;
    std::memcpy(&dsid_length, cur, sizeof(dsid_length));
    END_IF(dsid_length > 60 || dsid_length < 20);
    cur += sizeof(dsid_length);
    ss << (uint)dsid_length << std::endl;

    /* save DSID */
    checking(ss, "broker DSID", true);
    byte new_dsid[1000];
    std::memcpy(new_dsid, cur, dsid_length);
    cur += dsid_length;
    broker_dsid.assign(new_dsid, new_dsid + dsid_length);
    // END_IF(cur > buf + message_size);
    ss << "done" << std::endl;

    /* save public key */
    checking(ss, "broker public key", true);
    byte tmp_pub[65];
    std::memcpy(tmp_pub, cur, sizeof(tmp_pub));
    cur += sizeof(tmp_pub);
    broker_public.assign(tmp_pub, tmp_pub + sizeof(tmp_pub));
    ss << "done" << std::endl;

    /* save broker salt */
    checking(ss, "broker salt", true);
    byte tmp_salt[32];
    std::memcpy(tmp_salt, cur, sizeof(tmp_salt));
    cur += sizeof(broker_salt);
    broker_salt.assign(tmp_salt, tmp_salt + sizeof(tmp_salt));
    // END_IF(cur != buf + message_size);
    ss << "done" << std::endl;

    std::cout << ss.str();

    static const auto wait_for_secret = [&]() {
      int f2_size = load_f2();
      boost::asio::async_write(
          sock, boost::asio::buffer(write_buf, f2_size),
          boost::bind(&client::f2_sent, this, boost::asio::placeholders::error,
                      boost::asio::placeholders::bytes_transferred));
    };
    strand.post(boost::bind(&client::compute_secret, this));
    strand.post(boost::bind<void>(wait_for_secret));
  }
}

void client::compute_secret() {
  shared_secret = ecdh.compute_secret(broker_public);

  /* compute client auth */
  dsa::hmac hmac("sha256", shared_secret);
  hmac.update(broker_salt);
  auth = hmac.digest();

  /* compute broker auth */
  dsa::hmac broker_hmac("sha256", shared_secret);
  broker_hmac.update(salt);
  broker_auth = broker_hmac.digest();
}

void client::f2_sent(const boost::system::error_code &err,
                     size_t bytes_transferred) {
  std::cout << std::endl;
  if (err) {
    std::stringstream ss;
    ss << "[clien::f2_sent] Error: " << err << std::endl;
    std::cerr << ss.str();
  } else {
    std::stringstream ss;
    ss << "f2 sent, " << bytes_transferred << " bytes transferred"
              << std::endl;
    std::cout << ss.str();
    sock.async_read_some(
        boost::asio::buffer(read_buf, max_length),
        boost::bind(&client::f3_received, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void client::f3_received(const boost::system::error_code &err,
                         size_t bytes_transferred) {
  std::cout << std::endl;
  if (err) {
    std::stringstream ss;
    ss << "[clien::f3_received] Error: " << err << std::endl;
    std::cerr << ss.str();
  } else {
    std::stringstream ss;
    ss << "f3 received, " << bytes_transferred << " bytes transferred"
              << std::endl;

    byte *cur = read_buf;

    /* check to make sure message size matches */
    checking(ss, "message size");
    uint32_t message_size;
    std::memcpy(&message_size, cur, sizeof(message_size));
    END_IF(message_size != bytes_transferred);
    cur += sizeof(message_size);
    ss << message_size << std::endl;

    /* check to make sure header length is correct */
    checking(ss, "header length");
    uint16_t header_size;
    std::memcpy(&header_size, cur, sizeof(header_size));
    END_IF(header_size != 11);
    cur += sizeof(header_size);
    ss << header_size << std::endl;

    /* check to make sure message type is correct */
    checking(ss, "message type");
    byte message_type;
    std::memcpy(&message_type, cur, sizeof(message_type));
    END_IF(message_type != 0xf3);
    cur += sizeof(message_type);
    ss << std::hex << (uint)message_type << std::dec << std::endl;

    /* check to make sure request id is correct */
    checking(ss, "request id");
    uint32_t request_id;
    std::memcpy(&request_id, cur, sizeof(request_id));
    END_IF(request_id != 0);
    cur += sizeof(request_id);
    ss << request_id << std::endl;

    /* check session id length */
    checking(ss, "session id length");
    uint16_t session_id_length;
    std::memcpy(&session_id_length, cur, sizeof(session_id_length));
    cur += sizeof(session_id_length);
    ss << session_id_length << std::endl;

    /* save session id */
    checking(ss, "session id", true);
    byte session[1000];
    std::memcpy(session, cur, session_id_length);
    cur += session_id_length;
    session_id.assign(session, session + session_id_length);
    ss << "done" << std::endl;

    /* check path length */
    checking(ss, "path length");
    uint16_t path_length;
    std::memcpy(&path_length, cur, sizeof(path_length));
    cur += sizeof(path_length);
    ss << path_length << std::endl;

    /* save path */
    checking(ss, "path", true);
    byte tmp_path[1000];
    std::memcpy(tmp_path, cur, path_length);
    cur += path_length;
    path.assign(tmp_path, tmp_path + path_length);
    ss << "done" << std::endl;

    /* check broker auth */
    checking(ss, "broker auth");
    for (int i = 0; i < 32; ++i)
      END_IF(*(cur++) != broker_auth[i]);
    ss << "done" << std::endl;

    ss << std::endl << "HANDSHAKE SUCCESSFUL" << std::endl;

    std::cout << ss.str();
  }
}

void write_LE(byte *buf, void *data, int len) {
  for (int i = 0; i < len; ++i) {
    buf[i] = ((byte *)data)[len - i - 1];
  }
}

void load_LE(byte *buf, void *data, int len) {
  for (int i = 0; i < len; ++i) {
    ((byte *)data)[i] = buf[len - i - 1];
  }
}

/**
 * f0 structure:
 * HEADER
 * total length :: Uint32 in LE                            :: 4 bytes
 * header length :: Uint16 in LE                           :: 2 bytes
 * handshake message type :: f0                            :: 1 byte
 * request id :: 0 for handshake messages                  :: 4 bytes
 *
 * BODY
 * dsa version major :: 2                                  :: 1 byte
 * dsa version minor :: 0                                  :: 1 byte
 * dsid length :: Uint8                                    :: 1 byte
 * dsid                                                    :: x bytes
 * public key                                              :: 65 bytes
 * security preference :: 0 = no encryption, 1 = encrypted :: 1 byte
 * client salt                                             :: 32 bytes
 */
int client::load_f0() {
  if (dsid.size() + f0_bytes_wo_dsid > max_length)
    throw std::runtime_error("buffer size too small");

  uint32_t total_size = 0;

  /* put placeholder for total length, 4 bytes */
  for (int i = 0; i < 4; ++i)
    write_buf[total_size++] = 0;

  /* header length, 2 bytes, LE */
  uint16_t header_length = 11;
  std::memcpy(&write_buf[total_size], &header_length, sizeof(header_length));
  total_size += 2;

  /* handshake message type f0, 1 byte */
  write_buf[total_size++] = 0xf0;

  /* request id (0 for handshake messages), 4 bytes */
  for (int i = 0; i < 4; ++i)
    write_buf[total_size++] = 0;

  /* dsa version major */
  write_buf[total_size++] = 2;

  /* dsa version minor */
  write_buf[total_size++] = 0;

  /* length of dsid */
  write_buf[total_size++] = dsid.size();

  /* dsid content */
  for (byte c : dsid)
    write_buf[total_size++] = c;

  /* public key, 65 bytes */
  for (byte c : public_key)
    write_buf[total_size++] = c;

  /* encryption preference, 1 byte */
  write_buf[total_size++] = 0; // no encryption

  /* salt, 32 bytes */
  // std::string salt = dsa::gen_salt(32);
  for (byte c : salt)
    write_buf[total_size++] = c;
  // ss << (uint32_t)salt[31] << std::endl;

  /* write total length */
  std::memcpy(write_buf, &total_size, sizeof(total_size));
  // write_LE(buf, &total_size, 4);

  return total_size;
}

/**
 * f2 structure:
 */
int client::load_f2() {
  uint32_t total = 0;

  /* total length placeholder */
  for (int i = 0; i < sizeof(total); ++i)
    write_buf[total++] = 0;

  /* header length */
  uint16_t header_length = 11;
  std::memcpy(&write_buf[total], &header_length, sizeof(header_length));
  total += sizeof(header_length);

  /* message type */
  write_buf[total++] = 0xf2;

  /* request id */
  for (int i = 0; i < 4; ++i)
    write_buf[total++] = 0;

  /* token length */
  uint16_t token_length = token.size();
  std::memcpy(&write_buf[total], &token_length, sizeof(token_length));
  total += sizeof(token_length);

  /* token */
  std::memcpy(&write_buf[total], token.c_str(), token_length);
  total += token_length;

  /* isRequester */
  write_buf[total++] = 1;

  /* isResponder */
  write_buf[total++] = 1;

  /* blank session string */
  write_buf[total++] = 0;

  /* auth */
  std::memcpy(&write_buf[total], &auth[0], auth.size());
  total += auth.size();

  /* write total length */
  std::memcpy(write_buf, &total, sizeof(total));

  return total;
}