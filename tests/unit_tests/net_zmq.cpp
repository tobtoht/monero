// Copyright (c) 2018-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <boost/thread/scoped_thread.hpp>
#include <gtest/gtest.h>

#include "byte_slice.h"
#include "crypto/crypto.h"
#include "net/zmq.h"

TEST(zmq, error_codes)
{
    EXPECT_EQ(
        std::addressof(net::zmq::error_category()),
        std::addressof(net::zmq::make_error_code(0).category())
    );
    EXPECT_EQ(
        std::make_error_condition(std::errc::not_a_socket),
        net::zmq::make_error_code(ENOTSOCK)
    );

    EXPECT_TRUE(
        []() -> expect<void>
        {
            MONERO_ZMQ_CHECK(zmq_msg_send(nullptr, nullptr, 0));
            return success();
        }().matches(std::errc::not_a_socket)
    );

    bool thrown = false;
    try
    {
        MONERO_ZMQ_THROW("stuff");
    }
    catch (const std::system_error& e)
    {
        thrown = true;
        EXPECT_EQ(std::make_error_condition(std::errc::not_a_socket), e.code());
    }
    EXPECT_TRUE(thrown);
}

TEST(zmq, read_write)
{
    net::zmq::context context{zmq_init(1)};
    ASSERT_NE(nullptr, context);

    net::zmq::socket send_socket{zmq_socket(context.get(), ZMQ_REQ)};
    net::zmq::socket recv_socket{zmq_socket(context.get(), ZMQ_REP)};
    ASSERT_NE(nullptr, send_socket);
    ASSERT_NE(nullptr, recv_socket);

    ASSERT_EQ(0u, zmq_bind(recv_socket.get(), "inproc://testing"));
    ASSERT_EQ(0u, zmq_connect(send_socket.get(), "inproc://testing"));

    std::string message;
    message.resize(1024);
    crypto::rand(message.size(), reinterpret_cast<std::uint8_t*>(std::addressof(message[0])));

    ASSERT_TRUE(bool(net::zmq::send(epee::strspan<std::uint8_t>(message), send_socket.get())));

    const expect<std::string> received = net::zmq::receive(recv_socket.get());
    ASSERT_TRUE(bool(received));
    EXPECT_EQ(message, *received);
}

TEST(zmq, read_write_slice)
{
    net::zmq::context context{zmq_init(1)};
    ASSERT_NE(nullptr, context);

    net::zmq::socket send_socket{zmq_socket(context.get(), ZMQ_REQ)};
    net::zmq::socket recv_socket{zmq_socket(context.get(), ZMQ_REP)};
    ASSERT_NE(nullptr, send_socket);
    ASSERT_NE(nullptr, recv_socket);

    ASSERT_EQ(0u, zmq_bind(recv_socket.get(), "inproc://testing"));
    ASSERT_EQ(0u, zmq_connect(send_socket.get(), "inproc://testing"));

    std::string message;
    message.resize(1024);
    crypto::rand(message.size(), reinterpret_cast<std::uint8_t*>(std::addressof(message[0])));

    {
        epee::byte_slice slice_message{{epee::strspan<std::uint8_t>(message)}};
        ASSERT_TRUE(bool(net::zmq::send(std::move(slice_message), send_socket.get())));
        EXPECT_TRUE(slice_message.empty());
    }

    const expect<std::string> received = net::zmq::receive(recv_socket.get());
    ASSERT_TRUE(bool(received));
    EXPECT_EQ(message, *received);
}

TEST(zmq, write_slice_fail)
{
    std::string message;
    message.resize(1024);
    crypto::rand(message.size(), reinterpret_cast<std::uint8_t*>(std::addressof(message[0])));

    epee::byte_slice slice_message{std::move(message)};
    EXPECT_FALSE(bool(net::zmq::send(std::move(slice_message), nullptr)));
    EXPECT_TRUE(slice_message.empty());
}

TEST(zmq, read_write_multipart)
{
    net::zmq::context context{zmq_init(1)};
    ASSERT_NE(nullptr, context);

    net::zmq::socket send_socket{zmq_socket(context.get(), ZMQ_REQ)};
    net::zmq::socket recv_socket{zmq_socket(context.get(), ZMQ_REP)};
    ASSERT_NE(nullptr, send_socket);
    ASSERT_NE(nullptr, recv_socket);

    ASSERT_EQ(0u, zmq_bind(recv_socket.get(), "inproc://testing"));
    ASSERT_EQ(0u, zmq_connect(send_socket.get(), "inproc://testing"));

    std::string message;
    message.resize(999);
    crypto::rand(message.size(), reinterpret_cast<std::uint8_t*>(std::addressof(message[0])));

    for (unsigned i = 0; i < 3; ++i)
    {
        const expect<std::string> received = net::zmq::receive(recv_socket.get(), ZMQ_DONTWAIT);
        ASSERT_FALSE(bool(received));
        EXPECT_EQ(net::zmq::make_error_code(EAGAIN), received.error());

        const epee::span<const std::uint8_t> bytes{
            reinterpret_cast<const std::uint8_t*>(std::addressof(message[0])) + (i * 333), 333
        };
        ASSERT_TRUE(bool(net::zmq::send(bytes, send_socket.get(), (i == 2 ? 0 : ZMQ_SNDMORE))));
    }

    const expect<std::string> received = net::zmq::receive(recv_socket.get(), ZMQ_DONTWAIT);
    ASSERT_TRUE(bool(received));
    EXPECT_EQ(message, *received);
}

TEST(zmq, read_write_termination)
{
    net::zmq::context context{zmq_init(1)};
    ASSERT_NE(nullptr, context);

    // must be declared before sockets and after context
    boost::scoped_thread<> thread{};

    net::zmq::socket send_socket{zmq_socket(context.get(), ZMQ_REQ)};
    net::zmq::socket recv_socket{zmq_socket(context.get(), ZMQ_REP)};
    ASSERT_NE(nullptr, send_socket);
    ASSERT_NE(nullptr, recv_socket);

    ASSERT_EQ(0u, zmq_bind(recv_socket.get(), "inproc://testing"));
    ASSERT_EQ(0u, zmq_connect(send_socket.get(), "inproc://testing"));

    std::string message;
    message.resize(1024);
    crypto::rand(message.size(), reinterpret_cast<std::uint8_t*>(std::addressof(message[0])));

    ASSERT_TRUE(bool(net::zmq::send(epee::strspan<std::uint8_t>(message), send_socket.get(), ZMQ_SNDMORE)));

    expect<std::string> received = net::zmq::receive(recv_socket.get(), ZMQ_DONTWAIT);
    ASSERT_FALSE(bool(received));
    EXPECT_EQ(net::zmq::make_error_code(EAGAIN), received.error());

    thread = boost::scoped_thread<>{
        boost::thread{
            [&context] () { context.reset(); }
        }
    };

    received = net::zmq::receive(recv_socket.get());
    ASSERT_FALSE(bool(received));
    EXPECT_EQ(net::zmq::make_error_code(ETERM), received.error());
}
