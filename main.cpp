#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>
#include <boost/asio/basic_raw_socket.hpp>
namespace asio = boost::asio;

#include "icmp_header.hpp"
#include "ipv4_header.hpp"
#include "tcp_header.hpp"
#include "raw.hpp"
#include <iostream>

using asio::steady_timer;
using asio::ip::icmp;
using asio::ip::tcp;
using asio::ip::udp;

namespace chrono = asio::chrono;

class pinger
{
  public:
    pinger(asio::io_context &io_context, boost::asio::io_service &io_service, const char *destination)
        : socket_(io_service), timer_(io_service), sequence_number_(0),
          num_replies_(0)
    {
        start_send();
        start_receive();
    }

    std::string get()
    {
        auto r = _output.str();
        _output.str("");
        return r;
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
        std::string body("");

        uint16_t port_to_scan = 80;

        boost::asio::ip::address destination_addr = boost::asio::ip::make_address("192.168.88.1");
        

        // Create an ICMP header for an echo request.
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

        syn_packet.destination_addr = destination_addr;
        syn_packet.source_addr = get_local_address();

        compute_checksum(syn_packet, body.begin(), body.end());

        boost::asio::streambuf request_buffer;
	    std::ostream os(&request_buffer);
	    os << syn_packet << body;
        // Encode the request packet.

        asio::ip::raw::endpoint test(destination_addr.to_v4(), port_to_scan);
        ep = test;

        try {
		    socket_.open();

            time_sent_ = steady_timer::clock_type::now();
		    socket_.send_to(request_buffer.data(), ep);

            num_replies_ = 0;
            timer_.expires_at(time_sent_ + chrono::seconds(5));
            timer_.async_wait(boost::bind(&pinger::handle_timeout, this));  
	    } catch (std::exception& e) {
		    std::cerr << "Error: " << e.what() << std::endl;
	    }
    }

    void handle_timeout()
    {
        if (num_replies_ == 0)
        {
            socket_.cancel(); // _output is set in response to error_code
        }
    }

    void start_receive()
    {
        //std::cout << "start_receive()\n";
        // Discard any data already in the buffer.

        reply_buffer_.consume(reply_buffer_.size());

        // Wait for a reply. We prepare the buffer to receive up to 64KB.
        socket_.async_receive_from(reply_buffer_.prepare(65536), ep,
                              boost::bind(&pinger::handle_receive, this, boost::asio::placeholders::error(),
                                          boost::asio::placeholders::bytes_transferred()));
    }

    void handle_receive(boost::system::error_code ec, std::size_t length)
    {
        //std::cout << "handle_receive()\n";
        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                _output << "Request timed out";
            }
            else
            {
                _output << "error: " << ec.message();
            }
            return;
        }

        
        reply_buffer_.commit(length);

        std::istream is(&reply_buffer_);
        ipv4_header ipv4_hdr;
        tcp_header tcp_hdr;
        is >> ipv4_hdr >> tcp_hdr;
        uint8_t proto = ipv4_hdr.protocol();
        if (is && (proto == 0x06) && ipv4_hdr.source_address() == boost::asio::ip::make_address_v4("192.168.88.1") && tcp_hdr.get_destport() == 80)
        {
            std::cout << "received reply!\n";
            std::cout << "length = " << length << "\n";
            std::cout << "src ip = " << ipv4_hdr.source_address() << std::endl;
            std::cout << "port = " << tcp_hdr.get_destport() << std::endl;
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

    std::ostringstream _output;
    boost::asio::io_service io_service;
    boost::asio::basic_raw_socket<asio::ip::raw> socket_;
    icmp::endpoint destination_;
    steady_timer timer_;
    unsigned short sequence_number_;
    chrono::steady_clock::time_point time_sent_;
    asio::streambuf reply_buffer_;
    std::size_t num_replies_;
    asio::ip::raw::endpoint ep;
};

#include <iostream>
#include <list>
int main(int argc, char **argv)
{
    asio::io_context io_context;
    boost::asio::io_service io_service;

    std::list<pinger> pingers;
    for (char const *arg : std::vector(argv + 1, argv + argc))
    {
        pingers.emplace_back(io_context, io_service, arg);
    }

    io_service.run();
    //io_context.run();
   

    for (auto &p : pingers)
    {
        std::cout << p.get() << std::endl;
    }
}
