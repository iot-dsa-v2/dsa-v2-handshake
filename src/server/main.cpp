#include "common.hpp"
#include <cstdlib>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>

boost::mutex mux;

void WorkerThread(boost::shared_ptr<boost::asio::io_service> io_service) {
  mux.lock();
  std::cout << "[" << boost::this_thread::get_id() << "] Worker start"
            << std::endl;
  mux.unlock();

  while (true) {
    try {
      boost::system::error_code err;

      io_service->run(err);

      if (err) {
        mux.lock();
        std::cerr << "[" << boost::this_thread::get_id() << "] Error: " << err
                  << std::endl;
        mux.unlock();
      } else {
        return;
      }
    } catch (std::exception &e) {
      mux.lock();
      std::cerr << "[" << boost::this_thread::get_id()
                << "] Exception: " << e.what() << std::endl;
      mux.unlock();
    }
  }

  mux.lock();
  std::cout << "[" << boost::this_thread::get_id() << "] Worker stop"
            << std::endl;
  mux.unlock();
}

int main(int argc, char *argv[]) {
  try {
    if (argc != 2) {
      std::cerr << "Usage: server <port>\n";
      return 1;
    }

    boost::shared_ptr<boost::asio::io_service> io_service(
        new boost::asio::io_service);
    boost::shared_ptr<boost::asio::io_service::work> work(
        new boost::asio::io_service::work(*io_service));

    boost::thread_group worker_threads;
    for (int i = 0; i < 5; ++i) {
      worker_threads.create_thread(boost::bind(&WorkerThread, io_service));
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(50));
    mux.lock();
    std::cout << std::endl;
    mux.unlock();

    server s(io_service, std::atoi(argv[1]));

    worker_threads.join_all();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}