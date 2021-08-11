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

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <chrono>
#include <exception>
#include <limits>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <thread>

// #define _STUN_DEBUG 1

namespace stun {
namespace details {
  static int constexpr binding_requests_max = 9;
  static std::chrono::milliseconds binding_requests_wait_time_max(1600);

  class file_descriptor {
  public:
    file_descriptor(int n) : m_fd(n) { }
    ~file_descriptor() {
      if (m_fd > 0)
        close(m_fd);
    }
    operator int() const { return m_fd; }
  private:
    int m_fd;
  };

  #ifdef _STUN_DEBUG
  void dump_buffer(char const * prefix, stun::buffer const & buff)
  {
    if (prefix)
      printf("%s", prefix);
    for (uint8_t b : buff)
      printf("0x%02x ", b);
    printf("\n");
  }
  #endif

  #ifdef _STUN_DEBUG
  #define STUN_TRACE(format, ...) printf("STUN:" format, __VA_ARGS__)
  #else
  #define STUN_TRACE(format, ...)
  #endif

  void throw_error(char const * format, ...)
  {
    char buff[256] = {};

    va_list ap;
    va_start(ap, format);
    vsnprintf(buff, sizeof(buff) - 1, format, ap);
    va_end(ap);

    buff[255] = '\0';

    throw std::runtime_error(buff);
  }

  template<typename iterator>
  inline void random_fill(iterator begin, iterator end) {
    std::random_device rdev;
    std::default_random_engine random_engine(rdev());
    std::uniform_int_distribution<uint8_t> uniform_dist(0, std::numeric_limits<uint8_t>::max());
    while (begin != end)
      *begin++ = uniform_dist(random_engine);
  }

  sockaddr_storage get_interface_address(std::string const & iface, int family)
  {
    bool found_iface_info = false;
    sockaddr_storage iface_info = {};

    struct ifaddrs * address_list = nullptr;
    if (getifaddrs(&address_list) == -1)
      throw_error("failed to find address for %s. %s", iface.c_str(),
        strerror(errno));

    for (auto * addr = address_list; addr != nullptr; addr = addr->ifa_next) {
      if (iface != addr->ifa_name)
        continue;
      if (family != addr->ifa_addr->sa_family)
        continue;
      iface_info = * reinterpret_cast<sockaddr_storage *>(addr->ifa_addr);
      iface_info.ss_family = addr->ifa_addr->sa_family;
      found_iface_info = true;
      break;
    }

    if (address_list)
      freeifaddrs(address_list);

    if (!found_iface_info)
      throw_error("failed to find ip for interface:%s", iface.c_str());

    STUN_TRACE("local_addr:%s\n", stun::sockaddr_to_string(iface_info).c_str());

    return iface_info;
  }

  std::string sockaddr_to_string2(sockaddr const * addr, int family)
  {
    char buff[INET6_ADDRSTRLEN] = {};

    char const * p = nullptr;

    if (family == AF_INET) {
      sockaddr_in const * v4 = reinterpret_cast< sockaddr_in const *>(addr);
      p = inet_ntop(AF_INET, &v4->sin_addr, buff, INET6_ADDRSTRLEN);
    }
    else if (family == AF_INET6) {
      sockaddr_in6 const * v6 = reinterpret_cast< sockaddr_in6 const *>(addr);
      p = inet_ntop(AF_INET6, &v6->sin6_addr, buff, INET6_ADDRSTRLEN);
    }
    else
      throw_error("can't convert address with family:%d to a string.", family);

    if (!p)
      throw_error("failed to convert address to string");

    buff[INET6_ADDRSTRLEN - 1] = '\0';
    return std::string(buff);
  }

  std::vector<sockaddr_storage> resolve_hostname(std::string const & host, uint16_t port)
  {
    std::vector<sockaddr_storage> addrs;
    std::set<std::string> already_seen;

    struct addrinfo * stun_addrs = nullptr;
    int ret = getaddrinfo(host.c_str(), nullptr, nullptr, &stun_addrs);
    if (ret != 0) {
      std::stringstream error_message;
      error_message << "getaddrinfo failed. %s";
      if (ret == EAI_SYSTEM)
        error_message << strerror(errno);
      else
        error_message << gai_strerror(ret);
      throw std::runtime_error(error_message.str());
    }

    for (struct addrinfo * addr = stun_addrs; addr; addr = addr->ai_next) {
      if (addr->ai_family != AF_INET && addr->ai_family != AF_INET6)
        continue;

      std::string const s = sockaddr_to_string2(addr->ai_addr, addr->ai_family);

      if (already_seen.find(s) == std::end(already_seen)) {
        struct sockaddr_storage temp = {};
        memcpy(&temp, addr->ai_addr, addr->ai_addrlen);

        if (addr->ai_family == AF_INET) {
          sockaddr_in * v4 = reinterpret_cast< sockaddr_in *>(&temp);
          v4->sin_port = ntohs(port);
        }
        else if (addr->ai_family == AF_INET6) {
          sockaddr_in6 * v6 = reinterpret_cast< sockaddr_in6 *>(&temp);
          v6->sin6_port = ntohs(port);
        }

        addrs.push_back(temp);
        already_seen.insert(s);
      }
    }

    if (stun_addrs)
      freeaddrinfo(stun_addrs);

    return addrs;
  }

  socklen_t socket_length(sockaddr_storage const & addr)
  {
    if (addr.ss_family == AF_INET)
      return sizeof(sockaddr_in);
    if (addr.ss_family == AF_INET6)
      return sizeof(sockaddr_in6);
    return 0;
  }

  stun::message * send_message(
    file_descriptor const & soc,
    sockaddr_storage const & remote_addr,
    stun::message const & req,
    std::chrono::milliseconds const & wait_time)
  {
    stun::buffer bytes = req.encode();

    STUN_TRACE("remote_addr:%s\n", stun::sockaddr_to_string(remote_addr).c_str());

    #ifdef _STUN_DEBUG
    dump_buffer("STUN >>> ", bytes);
    #endif

    ssize_t n = sendto(soc, &bytes[0], bytes.size(), 0, (sockaddr *) &remote_addr, socket_length(remote_addr));
    if (n < 0)
      throw_error("failed to send packet. %s", strerror(errno));

    bytes.resize(0);
    bytes.reserve(256);
    bytes.resize(256);

    sockaddr_storage from_addr = {};
    socklen_t len = sizeof(sockaddr_storage);

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(soc, &rfds);

    timeval timeout;
    timeout.tv_usec = 1000 * wait_time.count();
    timeout.tv_sec = 0;
    int ret = select(soc + 1, &rfds, nullptr, nullptr, &timeout);
    if (ret == 0)
      return nullptr;

    do {
      n = recvfrom(soc, &bytes[0], bytes.size(), MSG_WAITALL, (sockaddr *) &from_addr, &len);
    } while (n == -2 && errno == EINTR);

    if (n < 0)
      throw_error("error receiving on socket. %s", strerror(errno));
    else
      bytes.resize(n);

    #ifdef _STUN_DEBUG
    dump_buffer("STUN <<< ", bytes);
    #endif

    return stun::decoder::decode_message(bytes, nullptr);
  }

  int create_udp_socket(sockaddr_storage const & remote_addr, std::string const & local_iface)
  {
    int soc = socket(remote_addr.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (soc < 0)
      throw_error("error creating socket. %s", strerror(errno));
    if (!local_iface.empty()) {
      sockaddr_storage local_addr = get_interface_address(local_iface, remote_addr.ss_family);
      int ret = bind(soc, reinterpret_cast<sockaddr const *>(&local_addr), socket_length(local_addr));
      if (ret < 0) {
        int err = errno;
        close(soc);
        throw_error("failed to bind socket to local address '%s'. %s",
            stun::sockaddr_to_string(local_addr).c_str(), strerror(err));
      }
    }
    return soc;
  }
} } 
// end namespace stun::details

stun::buffer stun::message::encode() const
{
  buffer bytes;
  stun::encoder::encode_u16(bytes, m_header.message_type);
  stun::encoder::encode_u16(bytes, m_header.message_length);
  for (uint8_t b : m_header.transaction_id)
    bytes.push_back(static_cast<uint8_t>(b));
  for (stun::attribute const & v : m_attrs) {
    stun::encoder::encode_u16(bytes, v.type);
    stun::encoder::encode_u16(bytes, v.length);
    bytes.insert(std::end(bytes), std::begin(v.value), std::end(v.value));
  }
  return bytes;
}

stun::message * stun::message_factory::create_binding_request()
{
  stun::message * message = new stun::message();
  message->m_header.message_type = 1;
  message->m_header.message_length = 8;
  stun::details::random_fill(std::begin(message->m_header.transaction_id),
    std::end(message->m_header.transaction_id));

  // CHANGE-REQUEST
  message->m_attrs.push_back({3, 4, {0, 0, 0, 0}});

  return message;
}

void stun::client::verbose(char const * format, ...)
{
  if (!m_verbose)
    return;

  va_list ap;
  va_start(ap, format);
  printf("STUN:");
  vprintf(format, ap);
  va_end(ap);
}

bool stun::client::exec(std::string const & stun_server, uint16_t stun_port, std::string const & local_iface)
{
  bool found_public_address = false;

  int const inet_family = AF_INET;

  std::vector<sockaddr_storage> server_addresses = stun::details::resolve_hostname(stun_server, stun_port);
  for (sockaddr_storage const & addr : server_addresses) {
    if (addr.ss_family != inet_family)
      continue;

    std::chrono::milliseconds wait_time(250);
    std::unique_ptr<stun::message> binding_response;

    for (int i = 0; i < details::binding_requests_max; ++i) {
      stun::details::file_descriptor soc = stun::details::create_udp_socket(addr, local_iface);
      std::unique_ptr<stun::message> binding_request(stun::message_factory::create_binding_request());
      binding_response.reset(send_message(soc, addr, *binding_request, wait_time));
      if (binding_response)
        break;
      else
        wait_time = std::min(wait_time * 2, details::binding_requests_wait_time_max);
    }

    for (stun::attribute const & attr : binding_response->attributes()) {
      if (attr.type == stun::attribute_type::mapped_address) {
        found_public_address = true;
        m_public_address = stun::attributes::mapped_address(attr).addr();
        break;
      }
    }
  }

  return found_public_address;
}

stun::attributes::address::address(stun::attribute const & attr)
{
  size_t offset = 0;

  // the family is actually 8-bits, but the pkt has a 1 byte padding
  // for alignment
  uint16_t family = stun::decoder::decode_u16(attr.value, &offset);
  if (family == 1) {
    sockaddr_in * v4 = reinterpret_cast<sockaddr_in *>(&m_addr);
    v4->sin_port = stun::decoder::decode_u16(attr.value, &offset);
    v4->sin_addr.s_addr = htonl(stun::decoder::decode_u32(attr.value, &offset));
    m_addr = * reinterpret_cast<sockaddr_storage *>(v4);
    m_addr.ss_family = AF_INET;
  }
  else if (family == 2) {
    sockaddr_in6 * v6 = reinterpret_cast<sockaddr_in6 *>(&m_addr);
    v6->sin6_port = stun::decoder::decode_u16(attr.value, &offset);
    for (int i = 0; i < 16; ++i)
      v6->sin6_addr.s6_addr[i] = attr.value[offset + i];
    m_addr = * reinterpret_cast<sockaddr_storage *>(v6);
    m_addr.ss_family = AF_INET6;
  }
  else
    stun::details::throw_error("invalid mapped address family:%d", family);
}

uint32_t stun::decoder::decode_u32(buffer const & buff, size_t * offset)
{
  uint32_t const * p = reinterpret_cast<uint32_t const *>(&buff[*offset]);
  uint32_t value = ntohl(*p);
  *offset += 4;
  return value;
}

uint16_t stun::decoder::decode_u16(buffer const & buff, size_t * offset)
{
  uint16_t const * p = reinterpret_cast<uint16_t const *>(&buff[*offset]);
  uint16_t value = ntohs(*p);
  *offset += 2;
  return value;
}

stun::message * stun::decoder::decode_message(buffer const & buff, size_t * offset)
{
  size_t temp_offset = 0;
  if (offset)
    temp_offset = *offset;

  // TODO: use a factory
  // create  a map[ message_type ] = message_factory_method

  stun::message * message = nullptr;
  stun::message_header header;
  header.message_type = stun::decoder::decode_u16(buff, &temp_offset);
  header.message_length = stun::decoder::decode_u16(buff, &temp_offset);
  if (header.message_type == stun::message_type::binding_response) {
    for (size_t i = 0, n = header.transaction_id.size(); i < n; ++i)
      header.transaction_id[i] = buff[temp_offset++ + i];
    message = new stun::message();
    message->m_header = header;
    while (temp_offset < buff.size())
      message->m_attrs.push_back(stun::decoder::decode_attr(buff, &temp_offset)); 
  }
  else {
    // TODO: unsupported message type
  }

  if (offset)
    *offset = temp_offset;

  return message;
}

stun::attribute stun::decoder::decode_attr(buffer const & buff, size_t * offset)
{
  stun::attribute t = {};
  t.type = stun::decoder::decode_u16(buff, offset);
  t.length = stun::decoder::decode_u16(buff, offset);
  t.value.insert(std::end(t.value), std::begin(buff) + *offset,
      std::begin(buff) + *offset + t.length);
  *offset += t.value.size();
  return t;
}

void stun::encoder::encode_u16(buffer & buff, uint16_t n)
{
  uint16_t temp = htons(n);
  uint8_t * p = reinterpret_cast< uint8_t * >(&temp);
  buff.push_back(p[0]);
  buff.push_back(p[1]);
}

void stun::encoder::encode_u32(buffer & buff, uint32_t n)
{
  uint32_t temp = htons(n);
  uint8_t * p = reinterpret_cast<uint8_t *>(&temp);
  buff.push_back(p[0]);
  buff.push_back(p[1]);
  buff.push_back(p[2]);
  buff.push_back(p[3]);
}

std::string stun::sockaddr_to_string(sockaddr_storage const & addr)
{
  sockaddr const * temp = reinterpret_cast<sockaddr const *>(&addr);
  return stun::details::sockaddr_to_string2(temp, addr.ss_family);
}
