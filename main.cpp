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

struct stun_server {
  std::string hostname;
  uint16_t    port;
};

uint16_t to_uint16(char const * s)
{
  long int i = strtol(s, nullptr, 10);
  if (i == LONG_MIN) { }

  if (i == LONG_MAX) { }

  if (i > std::numeric_limits<uint16_t>::max()) { }

  return static_cast<uint16_t>(i);
}

void print_help()
{
  std::cout << std::endl;
  std::cout << "stunclient [args]" << std::endl;
  std::cout << "  --interface=<iface>     -i <iface>        "
    << "local interface to use" << std::endl;
  std::cout << "  --server=<hostname|ip>  -s <hostanme|ip>  "
    << "remote server hostanem or ip address" << std::endl;
  std::cout << "  --port=<port>           -i <port>         "
    << "remote server port number" << std::endl;
  std::cout << "  --help                  -h                "
    << "print this help" << std::endl;
  std::cout << std::endl;
}


int main(int argc, char * argv[])
{
  bool verbose = false;
  std::string local_iface;
  stun_server remote_server;

  std::vector< stun_server > default_stun_servers = {
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
      { nullptr, 0, 0, 0}
    };

    int option_index = 0;
    int c = getopt_long(argc, argv, "i:s:p:", long_options, &option_index);
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
      case '?':
        break;
    }
  }

  if (remote_server.hostname.empty() || remote_server.port == 0) {
    print_help();
    std::cout << "you need to supply stun server hostname and port" << std::endl;
    std::cout << "try one of these" << std::endl;
    for (stun_server const & s : default_stun_servers)
      std::cout << "\t-s " << s.hostname << " -p " << s.port << std::endl;
    std::cout << std::endl;
    exit(0);
  }

  stun::client client;

  try {
    if (client.exec(remote_server.hostname, remote_server.port, local_iface)) {
      sockaddr_storage wan_addr = client.public_address();
      std::cout << remote_server.hostname << " says:" << stun::sockaddr_to_string(wan_addr)
        << std::endl;
    }
  }
  catch (std::exception const & err) {
    std::cerr << "exception:" << err.what() << std::endl;
  }

  return 0;
}
