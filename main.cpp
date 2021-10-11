//
// Copyright [2021] [jacobgladish@yahoo.com]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include "stun_client.h"

#include <getopt.h>
#include <limits.h>
#include <stdlib.h>

#include <algorithm>
#include <iostream>

static int constexpr kDefaultNumberOfAttempts = 3;
static int constexpr kDefaultWaitIntervalMillis = 200;

template<typename T>
T to_int(char const * s)
{
  long n = strtol(s, nullptr, 10);
  if (n == LONG_MIN) {
    // TODO
  }
  if (n == LONG_MAX) {
    // TODO
  }
  if (n > std::numeric_limits<T>::max())
  {
    // TODO:
  }
  return static_cast<T>(n);
}

int32_t to_int32(char const * s)
{
  return to_int<int32_t>(s);
}

uint16_t to_uint16(char const * s)
{
  return to_int<uint16_t>(s);
}

void print_help()
{
  std::cout << std::endl;
  std::cout << "stunclient [args]" << std::endl;
  std::cout << "  --interface=<iface>     -i <iface>        "
    << "local interface to use" << std::endl;
  std::cout << "  --server=<hostname|ip>  -s <hostanme|ip>  "
    << "remote server hostanem or ip address" << std::endl;
  std::cout << "  --port=<port>           -p <port>         "
    << "remote server port number" << std::endl;
  std::cout << "  --verbose               -v                "
    << "verbose mode" << std::endl;
  std::cout << "  --retries=<n>           -r <n>            "
    << "Number of times to retry. Default:" << kDefaultNumberOfAttempts << std::endl;
  std::cout << "  --4|6                   -4|6              "
    << "Force ipv4 or ipv6" << std::endl;
  std::cout << "  --timeout=<ms>          -t <ms>           "
    << "Number of milliseconds between retries. Default:" << kDefaultWaitIntervalMillis << std::endl;
  std::cout << "  --help                  -h                "
    << "print this help" << std::endl;
  std::cout << std::endl;
}


int main(int argc, char * argv[])
{
  bool verbose = false;
  int num_attempts = kDefaultNumberOfAttempts;
  int interval_wait_time = kDefaultWaitIntervalMillis;

  std::string local_iface;
  stun::server remote_server;
  stun::protocol proto = stun::protocol::af_inet;

  std::vector< stun::server > default_stun_servers = {
    { "stun1.l.google.com", 19302 },
    { "stun2.l.google.com", 19302 },
    { "stun3.l.google.com", 19302 },
    { "stun4.l.google.com", 19302 }
  };

  /* for testing
  std::random_shuffle(std::begin(default_stun_servers), std::end(default_stun_servers));
  stun_server const default_remote_server = default_stun_servers[0];
  */

  while (true) {
    static struct option long_options[] = {
      { "interface",  required_argument, 0, 'i' },
      { "server",     required_argument, 0, 's' },
      { "port",       required_argument, 0, 'p' },
      { "help",       no_argument,       0, 'h' },
      { "verbose",    no_argument,       0, 'v' },
      { "retrties",   required_argument, 0, 'r' },
      { "timeout",    required_argument, 0, 't' },
      { "4",          no_argument,       0, '4' },
      { "6",          no_argument,       0, '6' },
      { nullptr, 0, 0, 0}
    };

    int option_index = 0;
    int c = getopt_long(argc, argv, "i:s:p:v46r:t:", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'h':
        print_help();
        exit(0);
        break;
      case 'i':
        local_iface = optarg;
        break;
      case 's':
        remote_server.hostname = optarg;
        break;
      case 'p':
        remote_server.port = to_uint16(optarg);
        break;
      case 'v':
        verbose = true;
        break;
      case '4':
        proto = stun::protocol::af_inet;
        break;
      case '6':
        proto = stun::protocol::af_inet6;
        break;
      case 'r':
        num_attempts = to_int32(optarg);
        break;
      case 't':
        interval_wait_time = to_int32(optarg);
        break;
      case '?':
        break;
    }
  }

  if (remote_server.hostname.empty() || remote_server.port == 0) {
    print_help();
    std::cout << "you need to supply stun server hostname and port" << std::endl;
    std::cout << "try one of these" << std::endl;
    for (stun::server const & s : default_stun_servers)
      std::cout << "\t-s " << s.hostname << " -p " << s.port << std::endl;
    std::cout << std::endl;
    exit(0);
  }

  int return_status = 0;

  stun::client client(local_iface, proto);
  if (verbose)
    client.set_verbose(true);

  try {
    bool done = false;
    std::chrono::milliseconds wait_time(interval_wait_time);
    for (int i = 0; !done && i < num_attempts; ++i) {
      std::unique_ptr<stun::message> binding_response = client.send_binding_request(remote_server, wait_time);
      if (binding_response) {
        stun::attribute const * mapped_address = binding_response->find_attribute(
            stun::attribute_type::mapped_address);
        if (mapped_address) {
          sockaddr_storage wan_addr = stun::attributes::mapped_address(*mapped_address).addr();
          std::cout << remote_server.hostname << " says:" << stun::sockaddr_to_string(wan_addr)
            << std::endl;
          // done = true;
        } else {
          std::cerr << "Got a binding response without any mapped address" << std::endl;
          return_status = 1;
        }
      } else {
        std::cerr << "No binding response" << std::endl;
        return_status = 2;
      }
    }
  }
  catch (std::exception const & err) {
    std::cerr << "exception:" << err.what() << std::endl;
    return_status = 3;
  }

  return return_status;
}
