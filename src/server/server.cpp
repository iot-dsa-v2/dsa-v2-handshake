#include "common.hpp"
#include <iostream>
#include <string>
#include <regex>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#include "crypto.hpp"

server::server(boost::shared_ptr<boost::asio::io_service> io_service, short port)
    : io_service(io_service), ecdh("secp256k1"),
      acceptor(*io_service, boost::asio::ip::tcp::endpoint(
                               boost::asio::ip::tcp::v4(), port)) {
  ecdh.set_private_key_hex("e4c386d0427062374f22545ea926fd94319220a6a71bfa9c126ed96045a8ca1e");
  dsa::hash hash("sha256");

  public_key = ecdh.get_public_key();
  hash.update(public_key);

  dsid = "broker-" + dsa::base64url(hash.digest_base64());

  session *new_session = new session(*this, io_service);
  acceptor.async_accept(new_session->socket(),
                        boost::bind(&server::handle_accept, this, new_session,
                                    boost::asio::placeholders::error));
}

void server::handle_accept(session *new_session,
                           const boost::system::error_code &error) {
  if (!error) {
    new_session->start();
    new_session = new session(*this, io_service);
    acceptor.async_accept(new_session->socket(),
                          boost::bind(&server::handle_accept, this, new_session,
                                      boost::asio::placeholders::error));
  } else {
    mux.lock();
    std::cout << "[" << boost::this_thread::get_id() << "] Error: " << error
              << std::endl;
    mux.unlock();
    delete new_session;
  }
}

void server::end_session(session *s) {
  delete s;
}