#include "webserver.h"

#include <memory>
#include <thread>
#include <vector>

#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include "Log.h"
#include "http-utils.h"
#include "rest-process.h"
#include "server_certificate.hpp"
#include "ws-process.h"

template <class Body, class Allocator>
void make_websocket_session(boost::beast::tcp_stream stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) {
    std::make_shared<plain_websocket_session>(std::move(stream))->run(std::move(req));
}

template <class Body, class Allocator>
void make_websocket_session(boost::beast::ssl_stream<boost::beast::tcp_stream> stream, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>> req) {
    std::make_shared<ssl_websocket_session>(std::move(stream))->run(std::move(req));
}

boost::beast::string_view mime_type(boost::beast::string_view path) {
    using boost::beast::iequals;
    auto const ext = [&path] {
        auto const pos = path.rfind(".");
        if (pos == boost::beast::string_view::npos)
            return boost::beast::string_view{};
        return path.substr(pos);
    }();
    if (iequals(ext, ".htm")) {
        return "text/html";
    }
    if (iequals(ext, ".html")) {
        return "text/html";
    }
    if (iequals(ext, ".php")) {
        return "text/html";
    }
    if (iequals(ext, ".css")) {
        return "text/css";
    }
    if (iequals(ext, ".txt")) {
        return "text/plain";
    }
    if (iequals(ext, ".js")) {
        return "application/javascript";
    }
    if (iequals(ext, ".json")) {
        return "application/json";
    }
    if (iequals(ext, ".xml")) {
        return "application/xml";
    }
    if (iequals(ext, ".swf")) {
        return "application/x-shockwave-flash";
    }
    if (iequals(ext, ".flv")) {
        return "video/x-flv";
    }
    if (iequals(ext, ".png")) {
        return "image/png";
    }
    if (iequals(ext, ".jpe")) {
        return "image/jpeg";
    }
    if (iequals(ext, ".jpeg")) {
        return "image/jpeg";
    }
    if (iequals(ext, ".jpg")) {
        return "image/jpeg";
    }
    if (iequals(ext, ".gif")) {
        return "image/gif";
    }
    if (iequals(ext, ".bmp")) {
        return "image/bmp";
    }
    if (iequals(ext, ".ico")) {
        return "image/vnd.microsoft.icon";
    }
    if (iequals(ext, ".tiff")) {
        return "image/tiff";
    }
    if (iequals(ext, ".tif")) {
        return "image/tiff";
    }
    if (iequals(ext, ".svg")) {
        return "image/svg+xml";
    }
    if (iequals(ext, ".svgz")) {
        return "image/svg+xml";
    }
    // return "application/text";
    return "application/octet-stream";
}

std::string path_cat(boost::beast::string_view base, boost::beast::string_view path) {
    if (base.empty()) {
        return std::string(path);
    }
    std::string result(base);
    char constexpr path_separator = '/';
    if (result.back() == path_separator) {
        result.resize(result.size() - 1);
    }
    result.append(path.data(), path.size());
    return result;
}

template <class Body, class Allocator>
boost::beast::http::message_generator handle_request(boost::beast::string_view doc_root, boost::beast::http::request<Body, boost::beast::http::basic_fields<Allocator>>&& req) {
    auto const bad_request = [&req](boost::beast::string_view why) {
        boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::bad_request, req.version()};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };
    if (req.target().empty() || req.target()[0] != '/' || req.target().find("..") != boost::beast::string_view::npos) {
        return bad_request("Illegal request-target");
    }
    auto requestInfo = parse_request(std::move(req));
    if (requestInfo.path != "/api/chassis/maps/current") {
        log_info << "request method: " << requestInfo.method;
        log_info << "request url: " << requestInfo.path;
        log_info << "request body: " << requestInfo.body;
    }
    if (requestInfo.path.starts_with("/api/")) {
        auto response = http_request(requestInfo);
        boost::beast::http::response<boost::beast::http::string_body> res;
        res.result(boost::beast::http::status::ok);
        res.body() = response.data;
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, "application/json");
        for (auto const& [name, value] : response.headers) {
            res.set(name, value);
        }
        res.content_length(response.data.size());
        res.keep_alive(requestInfo.keep_alive);
        res.prepare_payload();
        return res;
    } else {
        auto const not_found = [&requestInfo](boost::beast::string_view target) {
            boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::not_found, requestInfo.version};
            res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(boost::beast::http::field::content_type, "text/html");
            res.keep_alive(requestInfo.keep_alive);
            res.body() = "The resource '" + std::string(target) + "' was not found.";
            res.prepare_payload();
            return res;
        };
        auto const server_error = [&requestInfo](boost::beast::string_view what) {
            boost::beast::http::response<boost::beast::http::string_body> res{boost::beast::http::status::internal_server_error, requestInfo.version};
            res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(boost::beast::http::field::content_type, "text/html");
            res.keep_alive(requestInfo.keep_alive);
            res.body() = "An error occurred: '" + std::string(what) + "'";
            res.prepare_payload();
            return res;
        };
        if (requestInfo.method_verb != boost::beast::http::verb::get && requestInfo.method_verb != boost::beast::http::verb::head) {
            return bad_request("Unknown HTTP-method");
        }
        std::string result_path = path_cat(doc_root, requestInfo.path);
        if (requestInfo.path.back() == '/') {
            result_path.append("index.html");
        }
        boost::beast::error_code ec;
        boost::beast::http::file_body::value_type file_body;
        file_body.open(result_path.c_str(), boost::beast::file_mode::scan, ec);
        if (ec == boost::beast::errc::no_such_file_or_directory) {
            return not_found(requestInfo.path);
        }
        if (ec) {
            return server_error(ec.message());
        }
        auto const size = file_body.size();
        if (requestInfo.method_verb == boost::beast::http::verb::head) {
            boost::beast::http::response<boost::beast::http::empty_body> res{boost::beast::http::status::ok, requestInfo.version};
            res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(boost::beast::http::field::content_type, mime_type(result_path));
            res.content_length(size);
            res.keep_alive(requestInfo.keep_alive);
            return res;
        }
        boost::beast::http::response<boost::beast::http::file_body> res{std::piecewise_construct, std::make_tuple(std::move(file_body)),
            std::make_tuple(boost::beast::http::status::ok, requestInfo.version)};
        res.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(boost::beast::http::field::content_type, mime_type(result_path));
        res.content_length(size);
        res.keep_alive(requestInfo.keep_alive);
        return res;
    }
    return boost::beast::http::response<boost::beast::http::empty_body>{};
}

template <class Derived> class http_session {
public:
    http_session(boost::beast::flat_buffer buffer, std::shared_ptr<std::string const> const& doc_root) : doc_root_(doc_root), buffer_(std::move(buffer)) {}

protected:
    void do_read() {
        parser_.emplace();
        parser_->body_limit(100 * 1024 * 1024);
        boost::beast::get_lowest_layer(derived().stream()).expires_after(std::chrono::seconds(300));
        boost::beast::http::async_read(derived().stream(), buffer_, *parser_, boost::beast::bind_front_handler(&http_session::on_read, derived().shared_from_this()));
    }

    boost::beast::flat_buffer buffer_;

private:
    void on_read(boost::beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        if (ec == boost::beast::http::error::end_of_stream) {
            return derived().do_eof();
        }
        if (ec) {
            return fail(ec, "http_session on_read");
        }
        if (boost::beast::websocket::is_upgrade(parser_->get())) {
            boost::beast::get_lowest_layer(derived().stream()).expires_never();
            return make_websocket_session(derived().release_stream(), parser_->release());
        } else {
            queue_write(handle_request(*doc_root_, parser_->release()));
            if (response_queue_.size() < queue_limit) {
                do_read();
            }
        }
    }

    void queue_write(boost::beast::http::message_generator response) {
        response_queue_.push_back(std::move(response));
        if (response_queue_.size() == 1) {
            do_write();
        }
    }

    bool do_write() {
        bool const was_full = response_queue_.size() == queue_limit;
        if (!response_queue_.empty()) {
            boost::beast::http::message_generator msg = std::move(response_queue_.front());
            response_queue_.erase(response_queue_.begin());
            bool keep_alive = msg.keep_alive();
            boost::beast::async_write(derived().stream(), std::move(msg), boost::beast::bind_front_handler(&http_session::on_write, derived().shared_from_this(), keep_alive));
        }
        return was_full;
    }

    void on_write(bool keep_alive, boost::beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        if (ec) {
            return fail(ec, "http_session on_write");
        }
        if (!keep_alive) {
            return derived().do_eof();
        }
        // if (do_write()) {
        //     do_read();
        // }
    }

    Derived& derived() {
        return static_cast<Derived&>(*this);
    }

    static constexpr std::size_t queue_limit = 40; // max responses

    std::shared_ptr<std::string const> doc_root_;
    std::vector<boost::beast::http::message_generator> response_queue_;
    boost::optional<boost::beast::http::request_parser<boost::beast::http::string_body>> parser_;
};

class plain_http_session : public http_session<plain_http_session>, public std::enable_shared_from_this<plain_http_session> {
public:
    plain_http_session(boost::beast::tcp_stream&& stream, boost::beast::flat_buffer&& buffer, std::shared_ptr<std::string const> const& doc_root)
        : http_session<plain_http_session>(std::move(buffer), doc_root), stream_(std::move(stream)) {}

    void run() {
        do_read();
    }

    boost::beast::tcp_stream& stream() {
        return stream_;
    }

    boost::beast::tcp_stream release_stream() {
        return std::move(stream_);
    }

    void do_eof() {
        boost::beast::error_code ec;
        stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != boost::beast::errc::not_connected) {
            log_error << "do_eof " << ec.message();
            return;
        }
        if (stream_.socket().is_open()) {
            stream_.socket().close();
        }
    }

private:
    boost::beast::tcp_stream stream_;
};

class ssl_http_session : public http_session<ssl_http_session>, public std::enable_shared_from_this<ssl_http_session> {
public:
    ssl_http_session(boost::beast::tcp_stream&& stream, boost::asio::ssl::context& ctx, boost::beast::flat_buffer&& buffer, std::shared_ptr<std::string const> const& doc_root)
        : http_session<ssl_http_session>(std::move(buffer), doc_root), stream_(std::move(stream), ctx) {}

    void run() {
        boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
        stream_.async_handshake(boost::asio::ssl::stream_base::server, buffer_.data(), boost::beast::bind_front_handler(&ssl_http_session::on_handshake, shared_from_this()));
    }

    boost::beast::ssl_stream<boost::beast::tcp_stream>& stream() {
        return stream_;
    }

    boost::beast::ssl_stream<boost::beast::tcp_stream> release_stream() {
        return std::move(stream_);
    }

    void do_eof() {
        boost::beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
        stream_.async_shutdown(boost::beast::bind_front_handler(&ssl_http_session::on_shutdown, shared_from_this()));
    }

private:
    void on_handshake(boost::beast::error_code ec, std::size_t bytes_used) {
        if (ec) {
            return fail(ec, "ssl_http_session on_handshake");
        }
        buffer_.consume(bytes_used);
        do_read();
    }

    void on_shutdown(boost::beast::error_code ec) {
        if (ec) {
            return fail(ec, "ssl_http_session on_shutdown");
        }
    }

    boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
};

class detect_session : public std::enable_shared_from_this<detect_session> {
public:
    explicit detect_session(boost::asio::ip::tcp::socket&& socket, boost::asio::ssl::context& ctx, std::shared_ptr<std::string const> const& doc_root)
        : stream_(std::move(socket)), ctx_(ctx), doc_root_(doc_root) {}

    void run() {
        boost::asio::dispatch(stream_.get_executor(), boost::beast::bind_front_handler(&detect_session::on_run, shared_from_this()));
    }

private:
    void on_run() {
        stream_.expires_after(std::chrono::seconds(30));
        boost::beast::async_detect_ssl(stream_, buffer_, boost::beast::bind_front_handler(&detect_session::on_detect, shared_from_this()));
    }

    void on_detect(boost::beast::error_code ec, bool result) {
        if (ec) {
            return fail(ec, "detect_session on_detect");
        }
        if (result) {
            std::make_shared<ssl_http_session>(std::move(stream_), ctx_, std::move(buffer_), doc_root_)->run();
        } else {
            std::make_shared<plain_http_session>(std::move(stream_), std::move(buffer_), doc_root_)->run();
        }
    }

    boost::beast::tcp_stream stream_;
    boost::asio::ssl::context& ctx_;
    std::shared_ptr<std::string const> doc_root_;
    boost::beast::flat_buffer buffer_;
};

class listener : public std::enable_shared_from_this<listener> {
public:
    listener(boost::asio::io_context& ioc, boost::asio::ssl::context& ctx, boost::asio::ip::tcp::endpoint endpoint, std::shared_ptr<std::string const> const& doc_root)
        : ioc_(ioc), ctx_(ctx), acceptor_(boost::asio::make_strand(ioc)), doc_root_(doc_root) {
        boost::beast::error_code ec;
        acceptor_.open(endpoint.protocol(), ec);
        if (ec) {
            fail(ec, "listener open");
            return;
        }
        log_info << endpoint.address() << endpoint.port();
        acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
        if (ec) {
            fail(ec, "listener set_option");
            return;
        }
        acceptor_.bind(endpoint, ec);
        if (ec) {
            fail(ec, "listener bind");
            return;
        }
        acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            fail(ec, "listener listen");
            return;
        }
    }

    void run() {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(boost::asio::make_strand(ioc_), boost::beast::bind_front_handler(&listener::on_accept, shared_from_this()));
    }

    void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (ec) {
            fail(ec, "listener on_accept");
        } else {
            std::make_shared<detect_session>(std::move(socket), ctx_, doc_root_)->run();
        }
        do_accept();
    }

    boost::asio::io_context& ioc_;
    boost::asio::ssl::context& ctx_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<std::string const> doc_root_;
};

void start_server(int port, std::string const& doc_root, int thread_count) {
    auto const address = boost::asio::ip::make_address("0.0.0.0");
    boost::asio::io_context ioc{thread_count};
    boost::asio::ssl::context ctx{boost::asio::ssl::context::tlsv12};
    load_server_certificate(ctx);
    auto root_path = std::make_shared<std::string>(doc_root);
    std::make_shared<listener>(ioc, ctx, boost::asio::ip::tcp::endpoint{address, (boost::asio::ip::port_type)port}, root_path)->run();
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](boost::beast::error_code const&, int) { ioc.stop(); });
    std::vector<std::thread> threads;
    threads.reserve(thread_count - 1);
    for (auto i = thread_count - 1; i > 0; --i) {
        threads.emplace_back([&ioc] { ioc.run(); });
    }
    ioc.run();
    for (auto& thread : threads) {
        thread.join();
    }
}
