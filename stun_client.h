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
#ifndef STUN_CLIENT_H
#define STUN_CLIENT_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <netinet/in.h>

namespace stun
{

class encoder;
class decoder;
class message;
class message_factory;

using buffer = std::vector<uint8_t>;

static size_t constexpr transaction_id_length = 16;

namespace message_type {
  static uint16_t constexpr binding_request = 0x001;
  static uint16_t constexpr binding_response = 0x0101;
  static uint16_t constexpr binding_error_response = 0x0111;
  static uint16_t constexpr shared_secret_request = 0x0002;
  static uint16_t constexpr shared_secret_response = 0x0102;
  static uint16_t constexpr shared_secret_error_response = 0x0112;
}

namespace attribute_type {
  static uint16_t constexpr mapped_address = 0x001;
  static uint16_t constexpr source_address = 0x004;
  static uint16_t constexpr changed_address = 0x005;
}

struct attribute {
  uint16_t type;
  uint16_t length;
  std::vector<uint8_t> value;
};

namespace attributes {
  class mapped_address {
    public:
      mapped_address(attribute const & attr);
      inline sockaddr_storage addr() const {
        return m_addr;
      }
    private:
      sockaddr_storage m_addr;
  };
}

struct message_header {
  uint16_t message_type;
  uint16_t message_length;
  std::array<uint8_t, 16> transaction_id;
//  uint8_t transaction_id[transaction_id_length];
};

class message {
  friend class encoder;
  friend class decoder;
  friend class message_factory;
public:
  buffer encode() const;
  inline std::vector<attribute> const & attributes() const {
    return m_attrs;
  }
private:
  message_header  m_header;
  std::vector<attribute> m_attrs;
};

class message_factory final {
public:
  static message * create_binding_request();
};

class decoder final {
public:
  static uint16_t decode_u16(buffer const & buff, size_t * offset);
  static uint32_t decode_u32(buffer const & buff, size_t * offset);

  static message * decode_message(buffer const & buff, size_t * offset);

  static attribute decode_attr(buffer const & buff, size_t * offset);
};

class encoder final {
public:
  static void encode_u16(buffer & buff, uint16_t n);
  static void encode_u32(buffer & buff, uint32_t n);
};

class client {
public:
  bool exec(std::string const & stun_server, uint16_t stun_port, std::string const & local_iface = {});
  inline sockaddr_storage public_address() const {
    return m_public_address;
  }
  inline void set_verbose(bool b) {
    m_verbose = b;
  }
private:
  void verbose(char const * format, ...) __attribute__((format(printf, 2, 3)));
private:
  sockaddr_storage m_public_address;
  bool m_verbose = { false };
};

std::string sockaddr_to_string(sockaddr_storage const & addr);

}

#endif
