#include <totp/totp.h>

#include <totp/base32.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sstream>
#include <stdexcept>

namespace totp {
namespace {

constexpr std::uint64_t PERIOD = 30;
constexpr unsigned int DIGITS = 6;

std::string hmac_totp(const std::vector<unsigned char> &key, std::uint64_t counter) {
  std::array<unsigned char, 8> message{};

  for (int i = 7; i >= 0; --i) {
    message[static_cast<std::size_t>(i)] = static_cast<unsigned char>(counter & 0xff);
    counter >>= 8;
  }

  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_len = 0;

  if (!HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), message.data(), message.size(),
            digest.data(), &digest_len) ||
      digest_len < 20) {
    throw std::runtime_error("HMAC-SHA1 calculation failed.");
  }

  const int offset = digest[digest_len - 1] & 0x0f;

  const std::uint32_t binary = ((static_cast<std::uint32_t>(digest[offset]) & 0x7f) << 24) |
                               ((static_cast<std::uint32_t>(digest[offset + 1]) & 0xff) << 16) |
                               ((static_cast<std::uint32_t>(digest[offset + 2]) & 0xff) << 8) |
                               (static_cast<std::uint32_t>(digest[offset + 3]) & 0xff);

  const std::uint32_t otp = binary % 1000000;

  std::ostringstream out;
  out << std::setw(DIGITS) << std::setfill('0') << otp;
  return out.str();
}

} // namespace

Result generate(const std::string &secret) {
  const auto key = base32::base32_decode(secret);

  const auto now = std::chrono::system_clock::now();
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

  if (seconds < 0)
    throw std::runtime_error("System clock is before Unix epoch.");

  const auto timestamp = static_cast<std::uint64_t>(seconds);
  const auto counter = timestamp / PERIOD;
  const int remaining = static_cast<int>(PERIOD - (timestamp % PERIOD));

  return {hmac_totp(key, counter), remaining};
}

} // namespace totp
