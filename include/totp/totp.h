#pragma once

#include <string>

namespace totp {

struct Result {
    std::string code;
    int remaining_seconds;
};

Result generate(const std::string& base32_secret);

} // namespace totp
