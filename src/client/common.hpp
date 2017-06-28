#ifndef CLIENT_COMMON_HPP
#define CLIENT_COMMON_HPP

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <string>

extern boost::mutex mux;

class client {
  boost::asio::ip::tcp::socket sock;
  std::string dsid;
  std::string public_key;
  enum { max_length = 2048, f0_bytes_wo_dsid = 112 };
  unsigned char buf[max_length];

  int load_f0();

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