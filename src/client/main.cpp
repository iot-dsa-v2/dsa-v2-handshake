#include "common.hpp"
#include <cstdlib>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

#ifdef USE_SSL
#include <boost/asio/ssl.hpp>
#endif // USE_SSL

void WorkerThread(boost::shared_ptr<boost::asio::io_service> io_service) {
  std::stringstream ss;
  ss << "[" << boost::this_thread::get_id() << "] Worker start"
            << std::endl;
  std::cout << ss.str();

  while (true) {
    try {
      boost::system::error_code err;

      io_service->run(err);

      if (err) {
        ss.clear();
        ss << "[" << boost::this_thread::get_id() << "] Error: " << err
                  << std::endl;
        std::cout << ss.str();
      } else {
        return;
      }
    } catch (std::exception &e) {
      ss.clear();
      ss << "[" << boost::this_thread::get_id()
                << "] Exception: " << e.what() << std::endl;
      std::cout << ss.str();
    }
  }

  ss.clear();
  ss << "[" << boost::this_thread::get_id() << "] Worker stop"
            << std::endl;
  std::cout << ss.str();
}

int main(int argc, char *argv[]) {
#ifdef USE_SSL
  std::cout << "Using secure TCP" << std::endl << std::endl;
#endif // USE_SSL

  try {
    if (argc < 3) {
      std::cout << "Usage: client <host> <port>" << std::endl;
      return 1;
    }

    boost::shared_ptr<boost::asio::io_service> io_service(
        new boost::asio::io_service);
    boost::shared_ptr<boost::asio::io_service::work> work(
        new boost::asio::io_service::work(*io_service));

    boost::thread_group worker_threads;
    for (int i = 0; i < 5; ++i) {
      worker_threads.create_thread(boost::bind(WorkerThread, io_service));
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
    std::cout << std::endl;
    
#ifndef USE_SSL // don't USE_SSL
    client c(io_service, argv[1], std::atoi(argv[2]));
#else // USE_SSL
    boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
    ctx.load_verify_file("certificate.pem");

    client c(io_service, argv[1], std::atoi(argv[2]), ctx);
#endif // USE_SSL

    worker_threads.join_all();
  } catch (std::exception &e) {
    std::cerr << "[main] Exception: " << e.what() << std::endl;
  }

  return 0;
}