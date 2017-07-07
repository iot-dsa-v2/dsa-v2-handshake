#include "session.hpp"
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

#include "server.hpp"

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#endif // USE_SSL

#define END_IF(X)                                                              \
  if (X) {                                                                     \
    ss << "fail" << std::endl;                                                 \
    std::cout << ss.str();                                                     \
    serv.end_session(this);                                                    \
    return;                                                                    \
  }

#ifdef USE_SSL
session::session(server &s, boost::shared_ptr<boost::asio::io_service> io_service,
                         boost::asio::ssl::context &context)
    : serv(s), sock(*io_service, context), strand(*io_service) {
#else  // don't USE_SSL
session::session(server &s,
                         boost::shared_ptr<boost::asio::io_service> io_service)
    : serv(s), sock(*io_service), strand(*io_service) {
#endif // USE_SSL
  std::stringstream ss;
  ss << std::setw(5) << std::setfill('0') << serv.get_session_id();
  session_id = ss.str();
  path = "/fake/path";
  salt = dsa::gen_salt(32);
}

session::~session() {
  sock.close();

  std::stringstream ss;
  ss << "[" << session_id << "] Session ended" << std::endl;
  std::cout << ss.str();
}

#ifdef USE_SSL
void session::start() {
  sock.async_handshake(boost::asio::ssl::stream_base::server,
                       boost::bind(&session::handle_ssl_handshake,
                                   this, boost::asio::placeholders::error));
}

void session::handle_ssl_handshake(
    const boost::system::error_code &error) {
  if (!error) {
    sock.async_read_some(
        boost::asio::buffer(read_buf, max_length),
        boost::bind(&session::f0_received, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  } else {
    std::stringstream ss;
    ss  << "[session::handle_ssl_handshake] Error: " << error
              << std::endl;
    std::cout << ss.str();

    serv.end_session(this);
  }
}

ssl_socket::lowest_layer_type &session::socket() { return sock.lowest_layer(); }
#else  // don't USE_SSL
void session::start() {
  sock.async_read_some(
      boost::asio::buffer(read_buf, max_length),
      boost::bind(&session::f0_received, this,
                  boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

boost::asio::ip::tcp::socket &session::socket() { return sock; }
#endif // USE_SSL

void checking(std::stringstream &ss, const char *message, bool saving = false) {
  ss << (saving ? "saving " : "checking ");
  int i = 0;
  while (message[i] != '\0')
    ss << message[i++];
  while ((saving ? 7 : 9) + (i++) < 30)
    ss << '.';
}

void session::f0_received(const boost::system::error_code &err,
                                  size_t bytes_transferred) {
  if (err) {
    std::stringstream ss;
    ss << "[clien::f1_received] Error: " << err << std::endl;
    std::cout << ss.str();

    serv.end_session(this);
  } else {
    std::stringstream ss;
    ss << "f0 received, " << bytes_transferred << " bytes transferred"
              << std::endl;

    byte *cur = read_buf;

    /* check to make sure message size matches */
    checking(ss, "message size");
    uint32_t message_size;
    std::memcpy(&message_size, cur, sizeof(message_size));
    END_IF(message_size != bytes_transferred ||
           message_size < f0_bytes_wo_dsid);
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
    uint8_t message_type;
    std::memcpy(&message_type, cur, sizeof(message_type));
    END_IF(message_type != 0xf0);
    cur += sizeof(message_type);
    ss << std::hex << (uint)message_type << std::dec << std::endl;

    /* check to make sure request id is correct */
    checking(ss, "request id");
    uint32_t request_id;
    std::memcpy(&request_id, cur, sizeof(request_id));
    END_IF(request_id != 0);
    cur += sizeof(request_id);
    ss << request_id << std::endl;

    /* check DSA version */
    checking(ss, "DSA version");
    byte version[2];
    std::memcpy(version, cur, sizeof(version));
    END_IF(version[0] != 2 && version[1] != 0);
    cur += sizeof(version);
    ss << (uint)version[0] << '.' << (uint)version[1] << std::endl;

    /* check DSID length */
    checking(ss, "DSID length");
    byte dsid_length;
    std::memcpy(&dsid_length, cur, sizeof(dsid_length));
    END_IF(dsid_length > 60 || dsid_length < 20);
    cur += sizeof(dsid_length);
    ss << (uint)dsid_length << std::endl;

    /* save DSID */
    checking(ss, "client DSID", true);
    byte new_dsid[1000];
    std::memcpy(new_dsid, cur, dsid_length);
    cur += dsid_length;
    client_dsid = std::vector<byte>(new_dsid, new_dsid + dsid_length);
    // END_IF(cur > buf + message_size);
    ss << "done" << std::endl;

    /* save public key */
    checking(ss, "client public key", true);
    byte tmp_pub[65];
    std::memcpy(tmp_pub, cur, sizeof(tmp_pub));
    cur += sizeof(tmp_pub);
    client_public = std::vector<byte>(tmp_pub, tmp_pub + sizeof(tmp_pub));
    // END_IF(cur > buf + message_size);
    ss << "done" << std::endl;

    /* check encryption preference */
    checking(ss, "encryption preference", true);
    std::memcpy(&use_ssl, cur, sizeof(use_ssl));
    cur += sizeof(use_ssl);
    END_IF(use_ssl);
    ss << "done" << std::endl;

    /* save client salt */
    checking(ss, "client salt", true);
    byte tmp_salt[32];
    std::memcpy(tmp_salt, cur, sizeof(tmp_salt));
    cur += sizeof(tmp_salt);
    client_salt = std::vector<byte>(tmp_salt, tmp_salt + sizeof(tmp_salt));
    // END_IF(cur != buf + message_size);
    ss << "done" << std::endl << std::endl;
    std::cout << ss.str();

    strand.post(boost::bind(&session::compute_secret, this));

    int f1_size = load_f1();
    boost::asio::async_write(
        sock, boost::asio::buffer(write_buf, f1_size),
        boost::bind(&session::f1_sent, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void session::compute_secret() {
  shared_secret = serv.ecdh.compute_secret(client_public);

  /* compute broker auth */
  dsa::hmac hmac("sha256", shared_secret);
  hmac.update(client_salt);
  auth = hmac.digest();

  /* compute client auth */
  dsa::hmac client_hmac("sha256", shared_secret);
  client_hmac.update(salt);
  client_auth = client_hmac.digest();
}

void session::f1_sent(const boost::system::error_code &error,
                              size_t bytes_transferred) {
  if (error) {
    std::stringstream ss;
    ss << "[session::f1_sent] Error: " << error << std::endl;
    std::cerr << ss.str();

    serv.end_session(this);
  } else {
    std::stringstream ss;
    ss << "f1 sent, " << bytes_transferred << " bytes transferred"
              << std::endl;
    std::cout << ss.str();

    const auto wait_for_secret = [&](const boost::system::error_code &error,
                                     size_t bytes_transferred) {
      strand.post(boost::bind(&session::f2_received, this, error,
                              bytes_transferred));
    };
    sock.async_read_some(
        boost::asio::buffer(read_buf, max_length),
        boost::bind<void>(wait_for_secret, boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred));
  }
}

void session::f2_received(const boost::system::error_code &error,
                                  size_t bytes_transferred) {
  std::cout << std::endl;
  if (error) {
    std::stringstream ss;
    ss << "[session::f2_received] Error: " << error << std::endl;
    std::cerr << ss.str();
  } else {
    std::stringstream ss;
    ss << "f2 received, " << bytes_transferred << " bytes transferred"
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
    uint8_t message_type;
    std::memcpy(&message_type, cur, sizeof(message_type));
    END_IF(message_type != 0xf2);
    cur += sizeof(message_type);
    ss << std::hex << (uint)message_type << std::dec << std::endl;

    /* check to make sure request id is correct */
    checking(ss, "request id");
    uint32_t request_id;
    std::memcpy(&request_id, cur, sizeof(request_id));
    END_IF(request_id != 0);
    cur += sizeof(request_id);
    ss << request_id << std::endl;

    /* check token length */
    checking(ss, "token length");
    uint16_t token_length;
    std::memcpy(&token_length, cur, sizeof(token_length));
    cur += sizeof(token_length);
    ss << token_length << std::endl;

    /* save token */
    checking(ss, "client token", true);
    byte token[1000];
    std::memcpy(token, cur, token_length);
    // client_token = std::vector<byte>(token, token + token_length);
    cur += token_length;
    ss << "done" << std::endl;

    /* check if requester */
    checking(ss, "if is requester");
    std::memcpy(&is_requester, cur, sizeof(is_requester));
    cur += sizeof(is_requester);
    ss << (is_requester ? "true" : "false") << std::endl;

    /* check if responder */
    checking(ss, "if is responder");
    std::memcpy(&is_responder, cur, sizeof(is_responder));
    cur += sizeof(is_responder);
    ss << (is_responder ? "true" : "false") << std::endl;

    /* skip blank session string */
    cur += 1;

    /* check client auth */
    checking(ss, "client auth");
    for (int i = 0; i < 32; ++i)
      END_IF(*(cur++) != client_auth[i]);
    ss << "done" << std::endl;
    std::cout << ss.str();

    int size = load_f3();
    boost::asio::async_write(
        sock, boost::asio::buffer(write_buf, size),
        boost::bind(&session::f3_sent, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void session::f3_sent(const boost::system::error_code &error,
                              size_t bytes_transferred) {
  if (error) {
    std::stringstream ss;
    ss << "[session::f3_sent] Error: " << error << std::endl;
    std::cout << ss.str();
  } else {
    std::stringstream ss;
    ss << std::endl;
    ss << "f3 sent, " << bytes_transferred << " bytes transferred"
              << std::endl;
    ss << std::endl << "HANDSHAKE SUCCESSFUL" << std::endl;
    std::cout << ss.str();

    sock.async_read_some(
        boost::asio::buffer(read_buf, max_length),
        boost::bind(&session::read_loop, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void session::read_loop(const boost::system::error_code &error,
                                size_t bytes_transferred) {
  if (!error) {
    sock.async_read_some(
        boost::asio::buffer(read_buf, max_length),
        boost::bind(&session::read_loop, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  } else {
    sock.close();
    serv.end_session(this);
  }
}

/**
 * f1 structure:
 * HEADER
 * total length :: Uint32 in LE                            :: 4 bytes
 * header length :: Uint16 in LE                           :: 2 bytes
 * handshake message type :: f1                            :: 1 byte
 * request id :: 0 for handshake messages                  :: 4 bytes
 *
 * BODY
 * dsid length :: Uint8                                    :: 1 byte
 * dsid                                                    :: x bytes
 * public key                                              :: 65 bytes
 * broker salt                                             :: 32 bytes
 */
int session::load_f1() {
  if (serv.dsid.size() + f0_bytes_wo_dsid > max_length)
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
  write_buf[total_size++] = 0xf1;

  /* request id (0 for handshake messages), 4 bytes */
  for (int i = 0; i < 4; ++i)
    write_buf[total_size++] = 0;

  /* length of dsid */
  write_buf[total_size++] = serv.dsid.size();

  /* dsid content */
  for (byte c : serv.dsid)
    write_buf[total_size++] = c;

  /* public key, 65 bytes */
  for (byte c : serv.public_key)
    write_buf[total_size++] = c;

  /* salt, 32 bytes */
  // std::string salt = dsa::gen_salt(32);
  for (byte c : salt)
    write_buf[total_size++] = c;
  // std::cout << (uint32_t)salt[31] << std::endl;

  /* write total length */
  std::memcpy(write_buf, &total_size, sizeof(total_size));
  // write_LE(buf, &total_size, 4);

  return total_size;
}

int session::load_f3() {
  uint32_t total = 0;

  /* total length placeholder */
  for (int i = 0; i < sizeof(total); ++i)
    write_buf[total++] = 0;

  /* header length */
  uint16_t header_length = 11;
  std::memcpy(&write_buf[total], &header_length, sizeof(header_length));
  total += sizeof(header_length);

  /* message type */
  write_buf[total++] = 0xf3;

  /* request id */
  for (int i = 0; i < 4; ++i)
    write_buf[total++] = 0;

  /* session id length */
  uint16_t id_length = session_id.size();
  std::memcpy(&write_buf[total], &id_length, sizeof(id_length));
  total += sizeof(id_length);

  /* session id */
  std::memcpy(&write_buf[total], session_id.c_str(), id_length);
  total += id_length;

  /* client path length */
  uint16_t path_length = path.size();
  std::memcpy(&write_buf[total], &path_length, sizeof(path_length));
  total += sizeof(path_length);

  /* client path */
  std::memcpy(&write_buf[total], path.c_str(), path_length);
  total += path_length;

  /* auth */
  std::memcpy(&write_buf[total], &auth[0], auth.size());
  total += auth.size();

  /* write total length */
  std::memcpy(write_buf, &total, sizeof(total));

  return total;
}