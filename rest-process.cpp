#include "rest-process.h"

#include <regex>
#include <unordered_map>
#include <utility>

#include <boost/json.hpp>

#include "Http.h"
#include "Log.h"

namespace {
    struct pair_hash {
        template <class T1, class T2> std::size_t operator()(const std::pair<T1, T2>& p) const {
            return std::hash<T1>{}(p.first) ^ std::hash<T2>{}(p.second);
        }
    };

    std::unordered_map<std::pair<std::string, std::string>, std::function<ResponseInfo(RequestInfo const& info)>, pair_hash> handlers_ = {
        {{"GET", "/api/info"}, [](auto const& request) {
            return ResponseInfo{};
        }},
    };
} // namespace

ResponseInfo http_request(RequestInfo const& info) noexcept {
    std::pair key{info.method, info.path};
    if (handlers_.find(key) != handlers_.end()) {
        return handlers_[key](info);
    } else {
        for (auto const& handler : handlers_) {
            if (handler.first.first == info.method) {
                std::string regex_path = std::regex_replace(handler.first.second, std::regex("\\{[0-9A-Za-z_-]+\\}"), "([0-9A-Za-z_-]+)");
                auto re = std::regex("^" + regex_path + "$");
                if (std::regex_match(info.path, re)) {
                    return handler.second(info);
                }
            }
        }
    }
    log_error << "No handler found for " << info.method << " " << info.path;
    return {};
}
