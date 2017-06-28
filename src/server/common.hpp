#ifndef SERVER_COMMON_HPP
#define SERVER_COMMON_HPP

#include <string>
#include <boost/asio.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include "crypto.hpp"

extern boost::mutex mux;

class server {
private:
  boost::shared_ptr<boost::asio::io_service> io_service;
  boost::asio::ip::tcp::acceptor acceptor;
  std::string dsid;
  std::string public_key;
  dsa::ecdh ecdh;

  class session : public boost::enable_shared_from_this<session> {
  private:
    server &serv;
    boost::asio::ip::tcp::socket sock;
    boost::asio::io_service::strand strand;
    enum { max_length = 512, f0_bytes_wo_dsid = 112 };
    unsigned char buf[max_length];
    std::string shared_secret;
    std::string client_dsid;
    byte client_public[65];
    bool use_ssl;
    byte client_salt[32];

    int load_f1();
    void compute_secret();

    void f0_received(const boost::system::error_code &err, size_t bytes_transferred);
    void f1_sent(const boost::system::error_code &err, size_t bytes_transferred);
    void read_f2();
    void f2_received(const boost::system::error_code &err, size_t bytes_transferred);
    void f3_sent(const boost::system::error_code &err, size_t bytes_transferred);

  public:
    session(server &s, boost::shared_ptr<boost::asio::io_service> io_service);

    boost::asio::ip::tcp::socket &socket();

    void start();

    void handle_read(const boost::system::error_code &error,
                    size_t bytes_transferred);

    void handle_write(const boost::system::error_code &error,
                      size_t bytes_transferred);
  };

public:
  server(boost::shared_ptr<boost::asio::io_service> io_service, short port);

  void handle_accept(session *new_session,
                     const boost::system::error_code &error);
};

#endif // SERVER_COMMON_HPP