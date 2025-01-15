#pragma once

#include <string>

#include "http-utils.h"

ResponseInfo http_request(RequestInfo const& info) noexcept;
