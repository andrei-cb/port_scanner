#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/asio/basic_raw_socket.hpp>
namespace asio = boost::asio;

#include "ipv4_header.hpp"
#include "tcp_header.hpp"
#include "raw.hpp"
#include <iostream>
#include <list>
#include "cxxopts.hpp"
#include <boost/format.hpp>

using asio::steady_timer;
using asio::ip::icmp;
using asio::ip::tcp;
using asio::ip::udp;

namespace chrono = asio::chrono;

class port_scanner
{
  public:
    port_scanner(boost::asio::io_service &io_service, std::string ip, std::vector<uint16_t> ports)
        : raw_socket(io_service), 
          recv_timer(io_service),
          ip_address(ip),
          ports(ports)
    {

    }

    void run()
    {
        start_send();
        start_receive();
    }

  private:
    boost::asio::ip::address get_local_address()
    {
        boost::asio::io_service netService;
        udp::resolver   resolver(netService);
        udp::resolver::query query(udp::v4(), "google.com", "");
        udp::resolver::iterator endpoints = resolver.resolve(query);
        udp::endpoint ep = *endpoints;
        udp::socket socket(netService);
        socket.connect(ep);
        return socket.local_endpoint().address();
    }

    void start_send()
    {
        std::string body(""); //to remove
        uint16_t port_to_scan = ports[0];

        boost::asio::ip::address destination_addr = boost::asio::ip::make_address(ip_address);
        
        tcp_header syn_packet;
        syn_packet.set_sourceport(port_to_scan);
        syn_packet.set_destport(port_to_scan);
        syn_packet.set_seq_number(1);
        syn_packet.set_ack_number(0);
        syn_packet.set_header_len(0x06);
        syn_packet.set_flags(syn_packet.flag_SYN);
        syn_packet.set_window_size(8192);

        syn_packet.set_urgent_ptr(0);
        syn_packet.set_options();

        syn_packet.set_dst_ip(destination_addr);
        syn_packet.set_src_ip(get_local_address());

        compute_checksum(syn_packet, body.begin(), body.end());

        asio::ip::raw::endpoint test(destination_addr.to_v4(), port_to_scan);
        ep = test;

        try {
		    raw_socket.open();

            time_sent_ = steady_timer::clock_type::now();

            for (auto port : ports)
            {
                boost::asio::streambuf request_buffer;
	            std::ostream os(&request_buffer);
                syn_packet.set_destport(port);
                syn_packet.set_sourceport(port);
                syn_packet.set_checksum(0);
                compute_checksum(syn_packet, body.begin(), body.end());
	            os << syn_packet << body;

                std::cout << "Sending packet to port " << syn_packet.get_destport() << "\n";
                raw_socket.send_to(request_buffer.data(), ep);
            }

            recv_timer.expires_at(time_sent_ + chrono::seconds(5));
            recv_timer.async_wait(boost::bind(&port_scanner::handle_timeout, this));  
	    } catch (std::exception& e) {
		    std::cout << "Error: " << e.what() << std::endl;
	    }
    }

    void handle_timeout()
    {
        //std::cout << "called handle_timeout()\n";
        raw_socket.cancel();
    }

    void start_receive()
    {
        reply_buffer_.consume(reply_buffer_.size());

        // Wait for a reply. We prepare the buffer to receive up to 64KB.
        raw_socket.async_receive_from(reply_buffer_.prepare(65536), ep,
                              boost::bind(&port_scanner::handle_receive, this, boost::asio::placeholders::error(),
                                          boost::asio::placeholders::bytes_transferred()));
    }

    void handle_receive(boost::system::error_code ec, std::size_t length)
    {
        //std::cout << "handle_receive()\n";
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
               // std::cout << "Request timed out";
            }
            else
            {
                //std::cout << "error: " << ec.message();
            }
            return;
        }

        
        reply_buffer_.commit(length);

        std::istream is(&reply_buffer_);
        ipv4_header ipv4_hdr;
        tcp_header tcp_hdr;
        is >> ipv4_hdr >> tcp_hdr;
        uint8_t proto = ipv4_hdr.protocol();
        if (is && 
           (proto == 0x06) && 
           (ipv4_hdr.source_address() == boost::asio::ip::make_address_v4(ip_address)) && 
           (std::any_of(ports.begin(), ports.end(), [&tcp_hdr](uint16_t val){ return val == tcp_hdr.get_destport(); })))
        {
            std::cout << boost::format("Port %d is opened for ip address %s\n") % tcp_hdr.get_destport() % ip_address;
        }

        start_receive();
    }

    static unsigned short get_identifier()
    {
#if defined(ASIO_WINDOWS)
        return static_cast<unsigned short>(::GetCurrentProcessId());
#else
        return static_cast<unsigned short>(::getpid());
#endif
    }

    std::string ip_address;
    std::vector<uint16_t> ports;
    boost::asio::io_service io_service;
    boost::asio::basic_raw_socket<asio::ip::raw> raw_socket;
    icmp::endpoint destination_;
    steady_timer recv_timer;
    chrono::steady_clock::time_point time_sent_;
    asio::streambuf reply_buffer_;
    std::size_t num_replies_;
    asio::ip::raw::endpoint ep;
};


int main(int argc, char **argv)
{
    boost::asio::io_service io_service;
    std::string ip_address;
    std::vector<uint16_t> ports;

    try{
        cxxopts::Options options("port_scanner", "Simple port scanner");

        options.add_options()
        ("ip", "IP address to scan", cxxopts::value<std::string>(ip_address))
        ("p,ports", "List of ports to scan separated by \",\"", cxxopts::value<std::vector<std::uint16_t>>(ports))
        ("h,help", "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help") || !result.count("ip") || !result.count("ports"))
        {
            std::cout << options.help() << std::endl;
            std::exit(0);
        }
    } catch (const cxxopts::exceptions::exception& e)
    {
        std::cout << "error parsing options: " << e.what() << std::endl;
        std::exit(1);
    }

    port_scanner ps(io_service, ip_address, ports);
    ps.run();

    io_service.run();
}
