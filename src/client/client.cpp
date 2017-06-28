#include "common.hpp"
#include <cstring>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>

#include "crypto.hpp"

#define END_IF(X)                                                              \
  if (X) {                                                                     \
    std::cout << "fail" << std::endl;                                          \
    return;                                                                    \
  }

client::client(boost::shared_ptr<boost::asio::io_service> io_service,
               char *host, int port)
    : sock(*io_service), strand(*io_service), ecdh("secp256k1") {
  boost::asio::ip::tcp::resolver resolver(*io_service);
  boost::asio::ip::tcp::resolver::query query(
      host, boost::lexical_cast<std::string>(port));
  boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
  boost::asio::ip::tcp::endpoint endpoint = *iterator;

  ecdh.set_private_key_hex(
      "e452e1d89dcd16e1ad31336c77f8eace1b1884c06c621aefb7670d47fe54d1f7");
  dsa::hash hash("sha256");

  public_key = ecdh.get_public_key();
  hash.update(public_key);

  dsid = "mlink-" + dsa::base64url(hash.digest_base64());

  std::cout << dsid << std::endl;

  sock.async_connect(endpoint, boost::bind(&client::start_handshake, this,
                                           boost::asio::placeholders::error));
}

void client::start_handshake(const boost::system::error_code &err) {
  if (err) {
    mux.lock();
    std::cerr << "[client::start_handshake] Error: " << err << std::endl;
    mux.unlock();
  } else {
    int size = load_f0();
    boost::asio::async_write(
        sock, boost::asio::buffer(buf, size),
        boost::bind(&client::f0_sent, this, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void client::f0_sent(const boost::system::error_code &err,
                     size_t bytes_transferred) {
  if (err) {
    mux.lock();
    std::cerr << "[clien::f0_sent] Error: " << err << std::endl;
    mux.unlock();
  } else {
    mux.lock();
    std::cout << "f0 sent, " << bytes_transferred << " bytes transferred"
              << std::endl;
    mux.unlock();
    sock.async_read_some(
        boost::asio::buffer(buf, max_length),
        boost::bind(&client::f1_received, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void client::f1_received(const boost::system::error_code &err,
                         size_t bytes_transferred) {
  if (err) {
    mux.lock();
    std::cerr << "[client::f1_received] Error: " << err << std::endl;
    mux.unlock();
  } else {
    mux.lock();
    std::cout << std::endl;
    std::cout << "f1 received, " << bytes_transferred << " bytes transferred"
              << std::endl;
    mux.unlock();

    auto checking = [](const char *d, bool saving = false) {
      std::cout << (saving ? "saving " : "checking ");
      int i = 0;
      while (d[i] != '\0')
        std::cout << d[i++];
      while ((saving ? 7 : 9) + (i++) < 30)
        std::cout << '.';
    };

    byte *cur = buf;

    auto debug = [&]() {
      std::cout << (uint) * (cur + 0) << std::endl;
      std::cout << (uint) * (cur + 1) << std::endl;
      std::cout << (uint) * (cur + 2) << std::endl;
      for (int i = 0; i < bytes_transferred; ++i) {
        if ((uint)buf[i] < 0x10)
          std::cout << 0;
        std::cout << std::hex << (uint)buf[i];
      }
      std::cout << std::endl;
      for (byte *ptr = buf; ptr < cur; ptr++)
        std::cout << "  ";
      std::cout << "^" << std::endl;
    };

    /* check to make sure message size matches */
    checking("message size");
    uint32_t message_size;
    std::memcpy(&message_size, cur, sizeof(message_size));
    END_IF(message_size != bytes_transferred);
    cur += sizeof(message_size);
    std::cout << message_size << std::endl;

    /* check to make sure header length is correct */
    checking("header length");
    uint16_t header_size;
    std::memcpy(&header_size, cur, sizeof(header_size));
    END_IF(header_size != 11);
    cur += sizeof(header_size);
    std::cout << header_size << std::endl;

    /* check to make sure message type is correct */
    checking("message type");
    uint8_t message_type;
    std::memcpy(&message_type, cur, sizeof(message_size));
    END_IF(message_type != 0xf1);
    cur += sizeof(message_type);
    std::cout << std::hex << (uint)message_type << std::endl;

    /* check to make sure request id is correct */
    checking("request id");
    uint32_t request_id;
    std::memcpy(&request_id, cur, sizeof(request_id));
    END_IF(request_id != 0);
    cur += sizeof(request_id);
    std::cout << request_id << std::endl;

    /* check DSID length */
    checking("DSID length");
    byte dsid_length;
    std::memcpy(&dsid_length, cur, sizeof(dsid_length));
    END_IF(dsid_length > 60 || dsid_length < 20);
    cur += sizeof(dsid_length);
    std::cout << (uint)dsid_length << std::endl;

    /* save DSID */
    checking("broker DSID", true);
    byte new_dsid[dsid_length];
    std::memcpy(new_dsid, cur, sizeof(new_dsid));
    new_dsid[dsid_length] = '\0';
    broker_dsid = reinterpret_cast<char *>(new_dsid);
    cur += sizeof(new_dsid);
    // END_IF(cur > buf + message_size);
    std::cout << "done" << std::endl;

    /* save public key */
    checking("client public key", true);
    std::memcpy(broker_public, cur, sizeof(broker_public));
    cur += sizeof(broker_public);
    // END_IF(cur > buf + message_size);
    std::cout << "done" << std::endl;

    /* save broker salt */
    checking("broker salt", true);
    std::memcpy(broker_salt, cur, sizeof(broker_salt));
    cur += sizeof(broker_salt);
    // END_IF(cur != buf + message_size);
    std::cout << "done" << std::endl;
    std::cout << std::endl;

    strand.post(boost::bind(&client::compute_secret, this));
  }
}

void client::compute_secret() {
  mux.lock();
  std::cout << "shared secret computation start" << std::endl;
  mux.unlock();
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  mux.lock();
  std::cout << "shared secret computation stop" << std::endl;
  mux.unlock();
  // sock.async_read_some(
  //     boost::asio::buffer(buf, max_length),
  //     boost::bind(&server::session::f2_received, this,
  //                 boost::asio::placeholders::error,
  //                 boost::asio::placeholders::bytes_transferred));
}

void client::f2_sent(const boost::system::error_code &err,
                     size_t bytes_transferred) {
  if (err) {
    mux.lock();
    std::cerr << "[clien::f2_sent] Error: " << err << std::endl;
    mux.unlock();
  } else {
    mux.lock();
    std::cout << "f2 sent, " << bytes_transferred << " bytes transferred"
              << std::endl;
    mux.unlock();
    sock.async_read_some(
        boost::asio::buffer(buf, max_length),
        boost::bind(&client::f3_received, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  }
}

void client::f3_received(const boost::system::error_code &err,
                         size_t bytes_transferred) {
  if (err) {
    mux.lock();
    std::cerr << "[clien::f3_received] Error: " << err << std::endl;
    mux.unlock();
  } else {
    mux.lock();
    std::cout << "f3 received, " << bytes_transferred << " bytes transferred"
              << std::endl;
    mux.unlock();
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
    throw("buffer size too small");

  uint32_t total_size = 0;

  /* put placeholder for total length, 4 bytes */
  for (int i = 0; i < 4; ++i)
    buf[total_size++] = 0;

  /* header length, 2 bytes, LE */
  uint16_t header_length = 11;
  std::memcpy(&buf[total_size], &header_length, sizeof(header_length));
  total_size += 2;

  /* handshake message type f0, 1 byte */
  buf[total_size++] = 0xf0;

  /* request id (0 for handshake messages), 4 bytes */
  for (int i = 0; i < 4; ++i)
    buf[total_size++] = 0;

  /* dsa version major */
  buf[total_size++] = 2;

  /* dsa version minor */
  buf[total_size++] = 0;

  /* length of dsid */
  buf[total_size++] = dsid.size();

  /* dsid content */
  for (byte c : dsid)
    buf[total_size++] = c;

  /* public key, 65 bytes */
  for (byte c : public_key)
    buf[total_size++] = c;

  /* encryption preference, 1 byte */
  buf[total_size++] = 0; // no encryption

  /* salt, 32 bytes */
  // std::string salt = dsa::gen_salt(32);
  std::vector<byte> salt = dsa::hex2bin(
      "c4ca4238a0b923820dcc509a6f75849bc81e728d9d4c2f636f067f89cc14862c");
  for (byte c : salt)
    buf[total_size++] = c;
  // std::cout << (uint32_t)salt[31] << std::endl;

  /* write total length */
  std::memcpy(buf, &total_size, sizeof(total_size));
  // write_LE(buf, &total_size, 4);

  return total_size;
}