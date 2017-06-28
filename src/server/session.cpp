#include "common.hpp"
#include <string>
#include <vector>
#include <cstring>
#include <boost/asio.hpp>
#include <boost/bind.hpp>

#define END_IF(X) if(X) { std::cout << "fail" << std::endl; delete this; return; }

server::session::session(server &s, boost::asio::io_service &io_service) 
  : serv(s), sock(io_service), strand(io_service) {}

boost::asio::ip::tcp::socket &server::session::socket() { return sock; }

void server::session::start() {
  sock.async_read_some(
      boost::asio::buffer(buf, max_length),
      boost::bind(&server::session::f0_received, this, boost::asio::placeholders::error,
                  boost::asio::placeholders::bytes_transferred));
}

void server::session::f0_received(const boost::system::error_code &err,
                         size_t bytes_transferred) {
  if (err) {
    mux.lock();
    std::cerr << "[clien::f1_received] Error: " << err << std::endl;
    mux.unlock();
  } else {
    mux.lock();
    std::cout << "f0 received, " << bytes_transferred << " bytes transferred"
              << std::endl;
    mux.unlock();

    auto checking = [](const char *d, bool saving=false) {
      std::cout << (saving ? "saving " : "checking ");
      int i = 0;
      while (d[i] != '\0')
        std::cout << d[i++];
      while ((saving ? 7 : 9) + (i++) < 30)
        std::cout << '.';
    };

    byte *cur = buf;
    
    auto debug = [&]() {
      std::cout << (uint)*(cur + 0) << std::endl;
      std::cout << (uint)*(cur + 1) << std::endl;
      std::cout << (uint)*(cur + 2) << std::endl;
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
    END_IF(message_size != bytes_transferred || message_size < f0_bytes_wo_dsid);
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
    END_IF(message_type != 0xf0);
    cur += sizeof(message_type);
    std::cout << std::hex << (uint)message_type << std::endl;

    /* check to make sure request id is correct */
    checking("request id");
    uint32_t request_id;
    std::memcpy(&request_id, cur, sizeof(request_id));
    END_IF(request_id != 0);
    cur += sizeof(request_id);
    std::cout << request_id << std::endl;

    /* check DSA version */
    checking("DSA version");
    byte version[2];
    std::memcpy(version, cur, sizeof(version));
    END_IF(version[0] != 2 && version[1] != 0);
    cur += sizeof(version);
    std::cout << (uint)version[0] << '.' << (uint)version[1] << std::endl;

    // debug();

    /* check DSID length */
    checking("DSID length");
    byte dsid_length;
    std::memcpy(&dsid_length, cur, sizeof(dsid_length));
    END_IF(dsid_length > 60 || dsid_length < 20);
    cur += sizeof(dsid_length);
    std::cout << (uint)dsid_length << std::endl;

    /* save DSID */
    checking("client DSID", true);
    byte new_dsid[dsid_length];
    std::memcpy(new_dsid, cur, sizeof(new_dsid));
    new_dsid[dsid_length] = '\0';
    client_dsid = reinterpret_cast<char *>(new_dsid);
    cur += sizeof(new_dsid);
    // END_IF(cur > buf + message_size);
    std::cout << "done" << std::endl;

    /* save public key */
    checking("client public key", true);
    std::memcpy(client_public, cur, sizeof(client_public));
    cur += sizeof(client_public);
    // END_IF(cur > buf + message_size);
    std::cout << "done" << std::endl;

    /* check encryption preference */
    checking("encryption preference", true);
    std::memcpy(&use_ssl, cur, sizeof(use_ssl));
    cur += sizeof(use_ssl);
    END_IF(use_ssl);
    std::cout << "done" << std::endl;

    /* save client salt */
    checking("client salt", true);
    std::memcpy(client_salt, cur, sizeof(client_salt));
    cur += sizeof(client_salt);
    // END_IF(cur != buf + message_size);
    std::cout << "done" << std::endl;

    // std::cout << client_dsid << std::endl;
  }
}

void server::session::handle_read(const boost::system::error_code &error,
                          size_t bytes_transferred) {
  if (!error) {
    boost::asio::async_write(
        sock, boost::asio::buffer(buf, bytes_transferred),
        boost::bind(&server::session::handle_write, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  } else {
    delete this;
  }
}

void server::session::handle_write(const boost::system::error_code &error,
                           size_t bytes_transferred) {
  if (!error) {
    sock.async_read_some(
        boost::asio::buffer(buf, max_length),
        boost::bind(&server::session::handle_read, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
  } else {
    delete this;
  }
}

void server::session::compute_secret(std::string client_public) {

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
int server::session::load_f1() {
  if (serv.dsid.size() + f0_bytes_wo_dsid > max_length)
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

  /* length of dsid */
  buf[total_size++] = serv.dsid.size();

  /* dsid content */
  for (byte c : serv.dsid)
    buf[total_size++] = c;

  /* public key, 65 bytes */
  for (byte c : serv.public_key)
    buf[total_size++] = c;

  /* salt, 32 bytes */
  // std::string salt = dsa::gen_salt(32);
  std::vector<byte> salt = dsa::hex2bin(
      "eccbc87e4b5ce2fe28308fd9f2a7baf3a87ff679a2f3e71d9181a67b7542122c");
  for (byte c : salt)
    buf[total_size++] = c;
  // std::cout << (uint32_t)salt[31] << std::endl;

  /* write total length */
  std::memcpy(buf, &total_size, sizeof(total_size));
  // write_LE(buf, &total_size, 4);

  return total_size;
}