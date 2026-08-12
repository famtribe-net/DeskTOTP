#include <totp/base32.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace base32 {
namespace {

int value(char c)
{
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    if (c >= 'A' && c <= 'Z')
        return c - 'A';

    if (c >= '2' && c <= '7')
        return c - '2' + 26;

    return -1;
}

} // namespace

std::vector<unsigned char> base32_decode(const std::string& input)
{
    std::vector<unsigned char> output;
    unsigned int buffer = 0;
    int bits = 0;

    for (char c : input) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == '-')
            continue;
        if (c == '=')
            break;

        const int v = value(c);
        if (v < 0)
            throw std::invalid_argument("Invalid Base32 character.");

        buffer = (buffer << 5) | static_cast<unsigned int>(v);
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            output.push_back(
                static_cast<unsigned char>((buffer >> bits) & 0xff)
            );
        }
    }

    if (output.empty())
        throw std::invalid_argument("TOTP secret is empty.");

    return output;
}

std::string normalize_base32_secret(const std::string& input)
{
    // Decode first so malformed input is rejected.
    (void)base32_decode(input);

    std::string result;
    for (char c : input) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == '-')
            continue;
        if (c == '=')
            break;
        result.push_back(
            static_cast<char>(std::toupper(static_cast<unsigned char>(c)))
        );
    }

    return result;
}

} // namespace base32
