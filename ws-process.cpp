#include "ws-process.h"

#include <memory>
#include <regex>
#include <unordered_map>

// #region stub
class Camera {
public:
    bool Prepare() {
        return true;
    }
    bool StreamOn() {
        return true;
    }
    void SetWebUsing(bool web_using) {}
    void StartRecord(int timeout, std::function<bool()>&& initialize, std::function<bool(std::byte* buffer, std::size_t length, long timestamp)>&& process, std::function<void()>&& cleanup, std::function<void(int code, std::string const& message)>&& notify) {}
    void StreamOff() {}
    void StopRecord() {}
    void Stop() {}
};

std::shared_ptr<Camera> get_camera_by_no(std::string const& serial_no) {
    return std::make_shared<Camera>();
}

namespace chassis {
    std::string generate_wsjson() {
        return "";
    }
}
// #endregion

namespace {
    enum class WebSocketType {
        PLAIN,
        SSL,
    };

    template <typename SessionPtr> std::shared_ptr<boost::asio::steady_timer> get_timer(SessionPtr session) {
        auto timer = session->get_timer();
        if (!timer) {
            session->init_timer();
            timer = session->get_timer();
        }
        return timer;
    }

    template <typename SessionPtr> void recursive_send(SessionPtr session, std::shared_ptr<boost::asio::steady_timer> timer) {
        std::string message = chassis::generate_wsjson();
        session->write(message);
        timer->expires_after(std::chrono::seconds(2));
        timer->async_wait([session, timer](boost::beast::error_code ec) {
            if (ec) {
                log_info << "do_write_chassis timer error: " << ec.message();
                timer->cancel();
                session->close();
            } else {
                log_trace << "timer_handler work";
                recursive_send(session, timer);
            }
        });
    }

    auto start_camera = []<typename WS>(WS& ws, std::string const& message, std::any context) {
        log_trace << "camera: " << message;
        if (message.length() > 7) {
            auto serial_no = message.substr(7);
            log_info << "camera: " << serial_no;
            std::shared_ptr<Camera> camera = get_camera_by_no(serial_no);
            if (camera) {
                bool result = true; // camera->Open();
                if (result) {
                    result = camera->Prepare();
                    if (result) {
                        result = camera->StreamOn();
                    }
                    if (result) {
                        camera->SetWebUsing(true);
                        camera->StartRecord(
                            0, [] { return true; },
                            [&ws](auto buffer, auto length, auto timestamp) {
                                bool result = false;
                                boost::beast::error_code ec;
                                try {
                                    if (ws.is_open()) {
                                        ws.binary(true);
                                        ws.write(boost::asio::buffer(std::string((char*)buffer, length)), ec);
                                        if (!ec) {
                                            result = true;
                                        }
                                    }
                                } catch (std::exception e) {
                                    log_error << "camera websocket catch: " << e.what();
                                }
                                return result;
                            },
                            [] { return true; }, [](auto code, auto msg) {});
                    }
                }
            }
        }
    };
    auto stop_camera = []<typename WS>(WS& ws, std::string const& message, std::any context) {
        log_trace << "camera_stop: " << message;
        if (message.length() > 12) {
            auto serial_no = message.substr(12);
            log_info << "camera_stop: " << serial_no;
            std::shared_ptr<Camera> camera = get_camera_by_no(serial_no);
            if (camera) {
                camera->SetWebUsing(false);
                camera->StopRecord();
                camera->StreamOff();
                camera->Stop();
                // camera->Close();
            }
        }
    };
    auto check = []<typename WS>(WS& ws, std::string const& message, std::any context) {};
    auto start_chassis = []<typename WS>(WS& ws, std::string const& message, std::any context) {
        auto station = std::any_cast<std::pair<WebSocketType, std::any>>(context);
        if (station.first == WebSocketType::PLAIN) {
            auto session = std::any_cast<std::shared_ptr<plain_websocket_session>>(station.second);
            auto timer = get_timer(session);
            recursive_send(session, timer);
        } else if (station.first == WebSocketType::SSL) {
            auto session = std::any_cast<std::shared_ptr<ssl_websocket_session>>(station.second);
            auto timer = get_timer(session);
            recursive_send(session, timer);
        }
    };
    auto stop_chassis = []<typename WS>(WS& ws, std::string const& message, std::any context) {
        auto station = std::any_cast<std::pair<WebSocketType, std::any>>(context);
        if (station.first == WebSocketType::PLAIN) {
            auto session = std::any_cast<std::shared_ptr<plain_websocket_session>>(station.second);
            auto timer = session->get_timer();
            if (timer) {
                timer->cancel();
            }
        } else if (station.first == WebSocketType::SSL) {
            auto session = std::any_cast<std::shared_ptr<ssl_websocket_session>>(station.second);
            auto timer = session->get_timer();
            if (timer) {
                timer->cancel();
            }
        }
    };

    std::unordered_map<std::string, std::function<void(boost::beast::websocket::stream<boost::beast::tcp_stream>& ws, std::string const& command, std::any context)>> ws_handlers_ =
        {
            {"camera:{serial-no}", start_camera},
            {"camera_stop:{serial-no}", stop_camera},
            {"check", check},
            {"chassis", start_chassis},
            {"chassis_stop", stop_chassis},
    };

    std::unordered_map<std::string,
        std::function<void(boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>& ws, std::string const& command, std::any context)>>
        wss_handlers_ = {
            {"camera:{serial-no}", start_camera},
            {"camera_stop:{serial-no}", stop_camera},
            {"check", check},
            {"chassis", start_chassis},
            {"chassis_stop", stop_chassis},
    };
} // namespace

void process_web_socket_message(boost::beast::websocket::stream<boost::beast::tcp_stream>& ws, std::string const& key, std::any context) noexcept {
    if (ws_handlers_.find(key) != ws_handlers_.end()) {
        return ws_handlers_[key](ws, key, std::make_pair(WebSocketType::PLAIN, context));
    } else {
        for (auto const& handler : ws_handlers_) {
            std::string regex_path = std::regex_replace(handler.first, std::regex("\\{[0-9A-Za-z_-]+\\}"), "([0-9A-Za-z_-]+)");
            auto re = std::regex("^" + regex_path + "$");
            if (std::regex_match(key, re)) {
                return handler.second(ws, key, std::make_pair(WebSocketType::PLAIN, context));
            }
        }
    }
    std::string result = "bad web socket info";
    boost::beast::error_code ec;
    size_t len = ws.write(boost::asio::buffer(result), ec);
}

void process_web_socket_message(boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>& ws, std::string const& key, std::any context) noexcept {
    if (wss_handlers_.find(key) != wss_handlers_.end()) {
        return wss_handlers_[key](ws, key, std::make_pair(WebSocketType::SSL, context));
    } else {
        for (auto const& handler : wss_handlers_) {
            std::string regex_path = std::regex_replace(handler.first, std::regex("\\{[0-9A-Za-z_-]+\\}"), "([0-9A-Za-z_-]+)");
            auto re = std::regex("^" + regex_path + "$");
            if (std::regex_match(key, re)) {
                return handler.second(ws, key, std::make_pair(WebSocketType::SSL, context));
            }
        }
    }
    std::string result = "bad web socket info";
    boost::beast::error_code ec;
    size_t len = ws.write(boost::asio::buffer(result), ec);
}
