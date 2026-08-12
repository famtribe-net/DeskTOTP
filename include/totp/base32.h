#pragma once

#include <string>
#include <vector>

namespace base32 {

std::vector<unsigned char> base32_decode(const std::string& input);
std::string normalize_base32_secret(const std::string& input);

} // namespace base32
