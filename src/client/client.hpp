#ifndef CLIENT_COMMON_HPP
#define CLIENT_COMMON_HPP

#include <array>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include "crypto.hpp"

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;
#endif // USE_SSL

#ifndef uint
typedef unsigned int uint;
#endif

class client {
  enum { max_length = 2048, f0_bytes_wo_dsid = 112 };
  byte write_buf[max_length];
  byte read_buf[max_length];

  std::string dsid;
  std::vector<byte> public_key;
  dsa::ecdh ecdh;
  std::vector<byte> shared_secret;
  std::vector<byte> broker_dsid;
  std::vector<byte> broker_public;
  std::vector<byte> broker_salt;
  std::vector<byte> broker_auth;
  std::vector<byte> session_id;
  std::vector<byte> path;
  std::string token;
  std::vector<byte> auth;
  std::vector<byte> salt;

  boost::asio::io_service::strand strand;

#ifndef USE_SSL  // don't USE_SSL
  boost::asio::ip::tcp::socket sock;
#else // USE_SSL
  ssl_socket sock;

  bool verify_certificate(bool preverified,
                          boost::asio::ssl::verify_context &ctx);
  
  void handle_ssl_handshake(const boost::system::error_code &err);
#endif // USE_SSL

  void compute_secret();

  int load_f0();
  int load_f2();

  void f0_sent(const boost::system::error_code &err, size_t bytes_transferred);
  void f1_received(const boost::system::error_code &err,
                   size_t bytes_transferred);
  void f2_sent(const boost::system::error_code &err, size_t bytes_transferred);
  void f3_received(const boost::system::error_code &err,
                   size_t bytes_transferred);

public:
#ifndef USE_SSL // don't USE_SSL
  client(boost::shared_ptr<boost::asio::io_service> io_service, char *host,
         int port);
#else // USE_SSL
  client(boost::shared_ptr<boost::asio::io_service> io_service, char *host,
         int port, boost::asio::ssl::context &context);
#endif // USE_SSL

  void start_handshake(const boost::system::error_code &error);

  void handle_write(const boost::system::error_code &error,
                    size_t bytes_transferred);
};

#endif // CLIENT_COMMON_HPP