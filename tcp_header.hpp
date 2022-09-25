//
// tcp_header.hpp
// ~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2020 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <algorithm>
#include <istream>
#include <ostream>
#include <boost/endian/conversion.hpp>
#include <boost/format.hpp>
#include <iostream>

//  0              8               16                             31
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |        Destination Port       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Acknowledgment Number                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Offset|  Res. |     Flags     |             Window            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Checksum           |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class tcp_header
{
  private:
    
  public:
    enum
    {
        flag_FIN = 0x01,
        flag_SYN = 0x02,
        flag_RST = 0x04,
        flag_PUSH = 0x08,
        flag_ACK = 0x10,
        flag_URG = 0x20,
    };

    tcp_header()
    {
        std::fill(raw_buff, raw_buff + sizeof(raw_buff), 0);
    }

    uint16_t get_sourceport() const {
        return (raw_buff[0] << 8) + raw_buff[1];
    }

    void set_sourceport(uint16_t port) {
        raw_buff[0] = port >> 8;
        raw_buff[1] = port & 0xFF;
    }

    uint16_t get_destport() const {
        return (raw_buff[2] << 8) + raw_buff[3];
    }

    void set_destport(uint16_t port) {
        raw_buff[2] = port >> 8;
        raw_buff[3] = port & 0xFF;
    }

    uint32_t get_seq_number() const {
        return (raw_buff[4] << 24) + (raw_buff[5] << 16) + (raw_buff[6] << 8) + raw_buff[7];
    }

    void set_seq_number(uint32_t seq_number) {
        raw_buff[4] = (seq_number >> 24) & 0xff;
        raw_buff[5] = (seq_number >> 16) & 0xff;
        raw_buff[6] = (seq_number >> 8) & 0xff;
        raw_buff[7] = seq_number & 0xff;

    }

    uint32_t get_ack_number() const {
        return (raw_buff[8] << 24) + (raw_buff[9] << 16) + (raw_buff[10] << 8) + raw_buff[11];
    }

    void set_ack_number(uint32_t ack_number) {
        raw_buff[8] = (ack_number >> 24) & 0xff;
        raw_buff[9] = (ack_number >> 16) & 0xff;
        raw_buff[10] = (ack_number >> 8) & 0xff;
        raw_buff[11] = ack_number & 0xff;
    }

    uint8_t get_header_len() const {
        return raw_buff[12] >> 4;
    }

    void set_header_len(uint8_t header_len) {
        raw_buff[12] = header_len << 4;
    }

    uint8_t get_flags() const {
        return raw_buff[13];
    }

    void set_flags(uint8_t flags) {
        raw_buff[13] = flags;
    }

    uint16_t get_window_size() const {
        return (raw_buff[14] << 8) + raw_buff[15];
    }

    void set_window_size(uint16_t window_size) {
        raw_buff[14] = window_size >> 8;
        raw_buff[15] = window_size & 0xff;
    }

    void set_checksum(uint16_t checksum)
    {
        raw_buff[16] = checksum >> 8;
        raw_buff[17] = checksum & 0xff;
    }

    uint16_t get_urgent_ptr() const {
        return (raw_buff[18] << 8) + raw_buff[19];;
    }

    void set_urgent_ptr(uint16_t urgent_ptr) {
        raw_buff[18] = urgent_ptr >> 8;
        raw_buff[19] = urgent_ptr & 0xff;
    }

    void set_options()
    {
        raw_buff[20] = 0x02;
        raw_buff[21] = 0x04;
        raw_buff[22] = 0x05;
        raw_buff[23] = 0xb4;
    }

    friend std::istream &operator>>(std::istream &is, tcp_header &header)
    {
        return is.read(reinterpret_cast<char *>(&header.raw_buff), 24);
    }

    friend std::ostream &operator<<(std::ostream &os, const tcp_header &header)
    {
        return os.write(reinterpret_cast<const char *>(&header.raw_buff), 24);
    }

    template <typename Iterator> friend void compute_checksum(tcp_header &header, Iterator body_begin, Iterator body_end);

    void set_dst_ip(boost::asio::ip::address dst_ip) {
        destination_addr = dst_ip;
    }

    void set_src_ip(boost::asio::ip::address src_ip) {
        source_addr = src_ip;
    }

private:
    unsigned char raw_buff[24] = {0};
    boost::asio::ip::address destination_addr;
    boost::asio::ip::address source_addr;


};

template <typename Iterator> void compute_checksum(tcp_header &header, Iterator body_begin, Iterator body_end)
{

    unsigned int sum = 0;
    struct ip_pseudo_header
    {
        uint32_t sourceip;
        uint32_t destip;
        uint8_t   zero;
        uint8_t   tcp_prot;
        uint16_t tcp_length;
    };

    unsigned char raw_pseudo_header[12] = {0};

    raw_pseudo_header[0] = header.source_addr.to_v4().to_bytes()[0];
    raw_pseudo_header[1] = header.source_addr.to_v4().to_bytes()[1];
    raw_pseudo_header[2] = header.source_addr.to_v4().to_bytes()[2];
    raw_pseudo_header[3] = header.source_addr.to_v4().to_bytes()[3];

    raw_pseudo_header[4] = header.destination_addr.to_v4().to_bytes()[0];
    raw_pseudo_header[5] = header.destination_addr.to_v4().to_bytes()[1];
    raw_pseudo_header[6] = header.destination_addr.to_v4().to_bytes()[2];
    raw_pseudo_header[7] = header.destination_addr.to_v4().to_bytes()[3];

    raw_pseudo_header[9] = 0x06;

    raw_pseudo_header[10] = 0;
    raw_pseudo_header[11] = 24; // tcp_length

    for (int i = 0; i < 12; i+=2)
    {
        /*if (i % 4 == 0)
        {
            std::cout << "\n";
        }
        std::cout << boost::format("%04x") % ((raw_pseudo_header[i] << 8) + raw_pseudo_header[i+1]);
        */
        sum += ((raw_pseudo_header[i] << 8) +raw_pseudo_header[i+1]);
    }

    for (int i = 0; i < 24; i+=2)
    {
        /*if (i % 4 == 0)
        {
            std::cout << "\n";
        }
        std::cout << boost::format("%04x") % ((header.raw_buff[i] << 8) + header.raw_buff[i+1]);
        */
        sum += ((header.raw_buff[i] << 8) + header.raw_buff[i+1]);
    }


    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    header.set_checksum(sum);
}