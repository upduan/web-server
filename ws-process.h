#pragma once

#include <any>

#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/bind_handler.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/fields.hpp>
#include <boost/beast/http/message_fwd.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket/stream.hpp>

#include "Log.h"
#include "http-utils.h"

void process_web_socket_message(boost::beast::websocket::stream<boost::beast::tcp_stream>& ws, std::string const& command, std::any context) noexcept;
void process_web_socket_message(boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>& ws, std::string const& command, std::any context) noexcept;

template <class Derived> class websocket_session {
public:
    template <class Body, class Allocator> void run(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) {
        auto requestInfo = parse_request(std::move(req));
        // TODO check method for this websocket, It's must equals to 'GET'
        // if (requestInfo.method == "GET") {}
        // TODO check target for this websocket, It's must starts with '/api/websockets/{sn}'
        // if (requestInfo.path.starts_with("/api/websockets/")) {}
        do_accept(std::move(req));
    }

    void init_timer() noexcept {
        release_timer();
        timer_ = derived().create_timer();
    }

    std::shared_ptr<boost::asio::steady_timer> get_timer() noexcept {
        return timer_;
    }

    void release_timer() noexcept {
        timer_ = nullptr;
    }

    void write(std::string const& content) noexcept {
        if (derived().ws().is_open()) {
            derived().ws().text(true);
            boost::beast::error_code ec;
            derived().ws().write(boost::asio::buffer(content), ec);
            if (ec) {
                log_info << "do_write_chassis write error: " << ec.message();
                close();
            }
        } else {
            log_error << "do_write_chassis web socket is closed";
        }
    }

    void write(std::vector<std::byte> const& content) noexcept {
        if (derived().ws().is_open()) {
            derived().ws().binary(true);
            boost::beast::error_code ec;
            derived().ws().write(boost::asio::buffer(content), ec);
            if (ec) {
                log_info << "do_write_chassis write error: " << ec.message();
                close();
            }
        } else {
            log_error << "do_write_chassis web socket is closed";
        }
    }

    void close() {
        // 取消定时器
        if (timer_) {
            timer_->cancel();
        }
        // 调用派生类的关闭方法（如果需要）
        static_cast<Derived*>(this)->shutdown();
    }

private:
    template <class Body, class Allocator> void do_accept(boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) {
        derived().ws().set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
        derived().ws().set_option(boost::beast::websocket::stream_base::decorator(
            [](boost::beast::websocket::response_type& res) { res.set(boost::beast::http::field::server, std::string(BOOST_BEAST_VERSION_STRING) + " advanced-server-flex"); }));
        derived().ws().async_accept(req, boost::beast::bind_front_handler(&websocket_session::on_accept, derived().shared_from_this()));
    }

    void on_accept(boost::beast::error_code ec) {
        if (ec) {
            if (timer_) {
                timer_->cancel();
            }
            close();
            fail(ec, "websocket_session on_accept");
        } else {
            log_info << "websocket_session on_accept " << (void*)this;
            do_read();
        }
    }

    void do_read() {
        derived().ws().async_read(buffer_, boost::beast::bind_front_handler(&websocket_session::on_read, derived().shared_from_this()));
    }

    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        if (ec == boost::beast::websocket::error::closed) {
            log_trace << "websocket_session on_read websocket closed";
            if (timer_) {
                timer_->cancel();
            }
            close();
            return;
        }
        if (ec) {
            if (timer_) {
                timer_->cancel();
            }
            close();
            return fail(ec, "websocket_session on_read");
        }
        derived().ws().text(derived().ws().got_text());
        auto data = buffer_.data();
        std::string wsinfo = std::string((char*)data.data(), data.size());
        if (wsinfo.size() >= 2 && wsinfo.front() == '\"' && wsinfo.back() == '\"') {
            wsinfo = wsinfo.substr(1, wsinfo.size() - 2);
        }
        process_web_socket_message(derived().ws(), wsinfo, derived().shared_from_this());
        buffer_.consume(buffer_.size());
        do_read();
    }

    void on_write(boost::beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        if (ec) {
            close();
            return fail(ec, "websocket_session on_write");
        }
        buffer_.consume(buffer_.size());
    }

    Derived& derived() {
        return static_cast<Derived&>(*this);
    }

    boost::beast::flat_buffer buffer_;
    std::shared_ptr<boost::asio::steady_timer> timer_ = nullptr;
};

class plain_websocket_session : public websocket_session<plain_websocket_session>, public std::enable_shared_from_this<plain_websocket_session> {
public:
    explicit plain_websocket_session(boost::beast::tcp_stream&& stream) : ws_(std::move(stream)) {}

    boost::beast::websocket::stream<boost::beast::tcp_stream>& ws() {
        return ws_;
    }

    std::shared_ptr<boost::asio::steady_timer> create_timer() noexcept {
        return std::make_shared<boost::asio::steady_timer>(ws_.get_executor());
    }

    bool shutdown() {
        bool success = true;
        if (ws_.is_open()) {
            boost::beast::error_code ec;
            // 发送 WebSocket 关闭帧
            ws_.close(boost::beast::websocket::close_code::normal, ec);
            if (ec) {
                log_error << "Error sending close frame: " << ec.message();
                success = false;
            }
        }
        // 关闭底层的 TCP 套接字
        if (ws_.next_layer().socket().is_open()) {
            boost::beast::error_code ec;
            ws_.next_layer().socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            if (ec) {
                log_error << "Error shutting down socket: " << ec.message();
                success = false;
            }
            ws_.next_layer().socket().close(ec);
            if (ec) {
                log_error << "Error closing socket: " << ec.message();
                success = false;
            }
        }
        return success;
    }

private:
    boost::beast::websocket::stream<boost::beast::tcp_stream> ws_;
};

class ssl_websocket_session : public websocket_session<ssl_websocket_session>, public std::enable_shared_from_this<ssl_websocket_session> {
public:
    explicit ssl_websocket_session(boost::beast::ssl_stream<boost::beast::tcp_stream>&& stream) : ws_(std::move(stream)) {}

    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>& ws() {
        return ws_;
    }

    std::shared_ptr<boost::asio::steady_timer> create_timer() noexcept {
        return std::make_shared<boost::asio::steady_timer>(ws_.next_layer().get_executor());
    }

    bool shutdown() {
        bool success = true;
        // 发送 WebSocket 关闭帧
        if (ws_.is_open()) {
            boost::beast::error_code ec;
            ws_.close(boost::beast::websocket::close_code::normal, ec);
            if (ec) {
                log_error << "Error sending WebSocket close frame: " << ec.message();
                success = false;
            }
        }
        // 优雅关闭 SSL 连接
        boost::beast::error_code ec;
        // 关闭 SSL 流
        ws_.next_layer().shutdown(ec);
        if (ec && ec != boost::asio::ssl::error::stream_truncated) {
            log_error << "SSL shutdown error: " << ec.message();
            success = false;
        }
        // 关闭底层 TCP 套接字
        if (ws_.next_layer().next_layer().socket().is_open()) {
            boost::beast::error_code socket_ec;
            ws_.next_layer().next_layer().socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, socket_ec);
            if (socket_ec && socket_ec != boost::asio::error::not_connected) {
                log_error << "SSL socket shutdown error: " << socket_ec.message();
                success = false;
            }
            // 关闭底层 TCP 套接字
            ws_.next_layer().next_layer().socket().close(socket_ec);
            if (socket_ec) {
                log_error << "Error closing SSL socket: " << socket_ec.message();
                success = false;
            }
        }
        return success;
    }

private:
    boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>> ws_;
};
