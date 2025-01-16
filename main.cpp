#include "Log.h"
#include "webserver.h"

int main() {
    util::Log::init("webserver", boost::log::trivial::trace);
    util::Log::start_clean_routine(7);
    start_server(8080, "/var/run/webserver", 40);
    util::Log::stop_clean_routine();
    return 0;
}
