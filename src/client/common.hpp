#ifndef CLIENT_COMMON_HPP
#define CLIENT_COMMON_HPP

#include <vector>
#include <array>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <string>

#include "crypto.hpp"

extern boost::mutex mux;

class client {
  boost::asio::ip::tcp::socket sock;
  boost::asio::io_service::strand strand;
  std::string dsid;
  std::vector<byte> public_key;
  enum { max_length = 2048, f0_bytes_wo_dsid = 112 };
  byte write_buf[max_length];
  byte read_buf[max_length];
  dsa::ecdh ecdh;
  std::vector<byte> shared_secret;
  std::vector<byte> broker_dsid;
  std::vector<byte> broker_public;
  std::vector<byte> broker_salt;
  std::string token;
  std::vector<byte> auth;

  void compute_secret();

  int load_f0();
  int load_f2();

  void f0_sent(const boost::system::error_code &err, size_t bytes_transferred);
  void f1_received(const boost::system::error_code &err, size_t bytes_transferred);
  void f2_sent(const boost::system::error_code &err, size_t bytes_transferred);
  void f3_received(const boost::system::error_code &err, size_t bytes_transferred);

public:
  client(boost::shared_ptr<boost::asio::io_service> io_service, char *host,
         int port);

  // void on_connect(const boost::system::error_code &err);

  void start_handshake(const boost::system::error_code &error);

  void handle_write(const boost::system::error_code &error,
                    size_t bytes_transferred);
};

#endif // CLIENT_COMMON_HPP