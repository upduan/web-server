#include "webserver.h"

int main() {
    start_server(8080, "/var/run/webserver", 40);
    return 0;
}
