//
// ipv4_header.hpp
// ~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef IPV4_HEADER_HPP
#define IPV4_HEADER_HPP

#include <algorithm>
#include <boost/asio/ip/address_v4.hpp>

// Packet header for IPv4.
//
// The wire format of an IPv4 header is:
//
// 0               8               16                             31
// +-------+-------+---------------+------------------------------+      ---
// |       |       |               |                              |       ^
// |version|header |    type of    |    total length in bytes     |       |
// |  (4)  | length|    service    |                              |       |
// +-------+-------+---------------+-+-+-+------------------------+       |
// |                               | | | |                        |       |
// |        identification         |0|D|M|    fragment offset     |       |
// |                               | |F|F|                        |       |
// +---------------+---------------+-+-+-+------------------------+       |
// |               |               |                              |       |
// | time to live  |   protocol    |       header checksum        |   20 bytes
// |               |               |                              |       |
// +---------------+---------------+------------------------------+       |
// |                                                              |       |
// |                      source IPv4 address                     |       |
// |                                                              |       |
// +--------------------------------------------------------------+       |
// |                                                              |       |
// |                   destination IPv4 address                   |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---
// |                                                              |       ^
// |                                                              |       |
// /                        options (if any)                      /    0 - 40
// /                                                              /     bytes
// |                                                              |       |
// |                                                              |       v
// +--------------------------------------------------------------+      ---

class ipv4_header
{
  public:
    ipv4_header()
    {
        std::fill(raw_buff, raw_buff + sizeof(raw_buff), 0);
    }

    unsigned char version() const
    {
        return (raw_buff[0] >> 4) & 0xF;
    }
    unsigned short header_length() const
    {
        return (raw_buff[0] & 0xF) * 4;
    }
    unsigned char type_of_service() const
    {
        return raw_buff[1];
    }
    unsigned short total_length() const
    {
        return (raw_buff[2] << 8) + raw_buff[3];
    }
    unsigned short identification() const
    {
        return (raw_buff[4] << 8) + raw_buff[5];
    }
    bool dont_fragment() const
    {
        return (raw_buff[6] & 0x40) != 0;
    }
    bool more_fragments() const
    {
        return (raw_buff[6] & 0x20) != 0;
    }
    unsigned short fragment_offset() const
    {
        return ((raw_buff[6] << 8) + raw_buff[7]) & 0x1FFF;
    }
    unsigned int time_to_live() const
    {
        return raw_buff[8];
    }
    unsigned char protocol() const
    {
        return raw_buff[9];
    }
    unsigned short header_checksum() const
    {
        return (raw_buff[10] << 8) + raw_buff[11];
    }

    boost::asio::ip::address_v4 source_address() const
    {
        boost::asio::ip::address_v4::bytes_type bytes = {{raw_buff[12], raw_buff[13], raw_buff[14], raw_buff[15]}};
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v4 destination_address() const
    {
        boost::asio::ip::address_v4::bytes_type bytes = {{raw_buff[16], raw_buff[17], raw_buff[18], raw_buff[19]}};
        return boost::asio::ip::address_v4(bytes);
    }

    friend std::istream &operator>>(std::istream &is, ipv4_header &header)
    {
        is.read(reinterpret_cast<char *>(header.raw_buff), 20);
        if (header.version() != 4)
            is.setstate(std::ios::failbit);
        std::streamsize options_length = header.header_length() - 20;
        if (options_length < 0 || options_length > 40)
            is.setstate(std::ios::failbit);
        else
            is.read(reinterpret_cast<char *>(header.raw_buff) + 20, options_length);
        return is;
    }

  private:

    unsigned char raw_buff[60];
};

#endif // IPV4_HEADER_HPP
