#include "form-data-parser.h"

namespace util::formdata {
    void parse(const char* content, std::size_t length, std::string const& boundary) {
        std::size_t offset = 0;
        State state = State::STATE_BOUNDARY;
        auto b = "--" + boundary + "\r\n";
        if (std::memcmp(content, b.data(), b.size()) == 0) {
            offset += b.size();
            state = State::STATE_FIELD_NAME;
        }
    }
} // namespace util::formdata
