#include <totp/cli.h>

#include <totp/base32.h>
#include <totp/clipboard.h>
#include <totp/keyring.h>
#include <totp/terminal.h>
#include <totp/totp.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace cli {
namespace {

std::string account_name(const std::string &value) {
  if (value.empty())
    throw std::runtime_error("Account name cannot be empty.");

  if (value.size() > 100)
    throw std::runtime_error("Account name is too long.");

  for (const char c : value) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '@' &&
        c != '+' && c != '-') {
      throw std::runtime_error("Invalid account name: " + value);
    }
  }

  return value;
}

void help() {
  std::cout << R"(totp - local TOTP authenticator

Usage:
  totp add ACCOUNT
  totp ACCOUNT [--watch] [--plain]
  totp get ACCOUNT [--watch] [--plain]
  totp copy ACCOUNT [--seconds N]
  totp list
  totp remove ACCOUNT
  totp test
  totp --help
)";
}

void show_code(const std::string &account, bool watch, bool plain) {
  const std::string secret = keyring::get(account);
  if (secret.empty())
    throw std::runtime_error("No TOTP secret is stored for account '" + account + "'.");

  do {
    const auto result = totp::generate(secret);

    if (plain)
      std::cout << '\r' << result.code << "       " << std::flush;
    else
      std::cout << '\r' << account << ": " << result.code << "  (" << result.remaining_seconds
                << "s remaining)   " << std::flush;

    if (!watch)
      break;

    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  } while (true);

  if (watch)
    std::cout << '\n';
}

void add(const std::string &account) {
  const bool replacing = keyring::exists(account);

  if (replacing) {
    std::cout << "Account '" << account << "' already exists. Replace it? [y/N] " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);

    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (answer != "y" && answer != "yes") {
      std::cout << "Not changed.\n";
      return;
    }
  }

  const std::string raw = terminal::read_hidden("TOTP secret: ");
  const std::string secret = base32::normalize_base32_secret(raw);

  keyring::put(account, secret);

  std::cout << "Account '" << account << "' " << (replacing ? "replaced" : "added") << ".\n";
  std::cout << "Current code: " << totp::generate(secret).code << '\n';
}

void copy_code(const std::string &account, int seconds) {
  const auto secret = keyring::get(account);
  if (secret.empty())
    throw std::runtime_error("No TOTP secret is stored for account '" + account + "'.");

  clipboard::copy(totp::generate(secret).code);

  std::cout << "TOTP code copied to clipboard.\n"
            << "Clipboard will be cleared in " << seconds << " seconds.\n";

  std::this_thread::sleep_for(std::chrono::seconds(seconds));
  clipboard::clear();

  std::cout << "Clipboard cleared.\n";
}

void test() {
  constexpr const char *account = "__totp_keyring_test__";
  constexpr const char *secret = "totp-cli-test";

  keyring::put(account, secret);

  if (keyring::get(account) != secret)
    throw std::runtime_error("Desktop keyring test failed.");

  keyring::remove(account);
  std::cout << "Desktop keyring: OK\n";
}

} // namespace

int run(int argc, char *argv[]) {
  if (argc < 2) {
    help();
    return 1;
  }

  std::vector<std::string> args(argv + 1, argv + argc);

  if (args[0] == "--help" || args[0] == "-h") {
    help();
    return 0;
  }

  if (args[0] == "test") {
    if (args.size() != 1)
      throw std::runtime_error("Usage: totp test");
    test();
    return 0;
  }

  if (args[0] == "list") {
    if (args.size() != 1)
      throw std::runtime_error("Usage: totp list");

    const auto list = keyring::accounts();
    if (list.empty()) {
      std::cout << "No TOTP accounts configured.\n";
    } else {
      std::cout << "Configured TOTP accounts:\n\n";
      for (const auto &account : list)
        std::cout << "  " << account << '\n';
    }
    return 0;
  }

  if (args[0] == "add") {
    if (args.size() != 2)
      throw std::runtime_error("Usage: totp add ACCOUNT");
    add(account_name(args[1]));
    return 0;
  }

  if (args[0] == "remove") {
    if (args.size() != 2)
      throw std::runtime_error("Usage: totp remove ACCOUNT");
    keyring::remove(account_name(args[1]));
    std::cout << "Account '" << args[1] << "' removed.\n";
    return 0;
  }

  if (args[0] == "get") {
    if (args.size() < 2)
      throw std::runtime_error("Usage: totp get ACCOUNT [--watch] [--plain]");

    bool watch = false;
    bool plain = false;

    for (std::size_t i = 2; i < args.size(); ++i) {
      if (args[i] == "--watch")
        watch = true;
      else if (args[i] == "--plain")
        plain = true;
      else
        throw std::runtime_error("Unknown option: " + args[i]);
    }

    show_code(account_name(args[1]), watch, plain);
    return 0;
  }

  if (args[0] == "copy") {
    if (args.size() < 2)
      throw std::runtime_error("Usage: totp copy ACCOUNT [--seconds N]");

    int seconds = 20;

    for (std::size_t i = 2; i < args.size(); ++i) {
      if (args[i] != "--seconds")
        throw std::runtime_error("Unknown option: " + args[i]);

      if (++i >= args.size())
        throw std::runtime_error("--seconds requires a value.");

      try {
        seconds = std::stoi(args[i]);
      } catch (...) {
        throw std::runtime_error("Invalid --seconds value.");
      }

      if (seconds < 1 || seconds > 3600)
        throw std::runtime_error("--seconds must be between 1 and 3600.");
    }

    copy_code(account_name(args[1]), seconds);
    return 0;
  }

  // Shorthand: totp ACCOUNT [--watch] [--plain]
  bool watch = false;
  bool plain = false;

  for (std::size_t i = 1; i < args.size(); ++i) {
    if (args[i] == "--watch")
      watch = true;
    else if (args[i] == "--plain")
      plain = true;
    else
      throw std::runtime_error("Unknown option: " + args[i]);
  }

  show_code(account_name(args[0]), watch, plain);
  return 0;
}

} // namespace cli
