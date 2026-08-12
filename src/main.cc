#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#include <glib.h>
#include <libsecret/secret.h>


namespace {

constexpr const char* APPLICATION = "totp-cli";
constexpr const char* SCHEMA_NAME = "org.famtribe.totp";

constexpr const char* INDEX_ACCOUNT = "__accounts__";

constexpr int TOTP_DIGITS = 6;
constexpr int TOTP_PERIOD = 30;


// ---------------------------------------------------------------------------
// Secret Service schema
// ---------------------------------------------------------------------------
//
// We use a custom schema:
//
//     org.famtribe.totp
//
// with one attribute:
//
//     account = "snappymail"
//
// The actual TOTP secret is the Secret Service "password" value.
//
// No secret is written to our filesystem.
// ---------------------------------------------------------------------------

SecretSchema make_totp_schema()
{
    SecretSchema schema{};

    schema.name = SCHEMA_NAME;
    schema.flags = SECRET_SCHEMA_NONE;

    schema.attributes[0].name = "account";
    schema.attributes[0].type = SECRET_SCHEMA_ATTRIBUTE_STRING;

    return schema;
}

const SecretSchema TOTP_SCHEMA = make_totp_schema();

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

class TotpError : public std::runtime_error {
public:
    explicit TotpError(const std::string& message)
        : std::runtime_error(message) {}
};


// ---------------------------------------------------------------------------
// Small RAII helper for GError
// ---------------------------------------------------------------------------

class GErrorPtr {
public:
    GError* ptr = nullptr;

    GErrorPtr() = default;

    ~GErrorPtr()
    {
        if (ptr) {
            g_error_free(ptr);
        }
    }

    GErrorPtr(const GErrorPtr&) = delete;
    GErrorPtr& operator=(const GErrorPtr&) = delete;
};

// ---------------------------------------------------------------------------
// Account name validation
// ---------------------------------------------------------------------------

std::string normalize_account(const std::string& input)
{
    std::string name = input;

    while (!name.empty() &&
           std::isspace(static_cast<unsigned char>(name.front()))) {
        name.erase(name.begin());
    }

    while (!name.empty() &&
           std::isspace(static_cast<unsigned char>(name.back()))) {
        name.pop_back();
    }

    if (name.empty()) {
        throw TotpError("Account name cannot be empty.");
    }

    if (name.size() > 100) {
        throw TotpError("Account name is too long.");
    }

    static const std::regex valid(
        R"([A-Za-z0-9_.@+-]+)"
    );

    if (!std::regex_match(name, valid)) {
        throw TotpError(
            "Account name may contain only letters, digits, "
            "'.', '_', '@', '+', and '-'."
        );
    }

    return name;
}


// ---------------------------------------------------------------------------
// Secret Service helpers
// ---------------------------------------------------------------------------

std::optional<std::string> lookup_secret(
    const std::string& account)
{
    GErrorPtr error;

    gchar* result = secret_password_lookup_sync(
        &TOTP_SCHEMA,
        nullptr,
        &error.ptr,
        "account",
        account.c_str(),
        nullptr
    );

    if (error.ptr) {
        throw TotpError(
            std::string("Unable to access the desktop keyring: ") +
            error.ptr->message
        );
    }

    if (!result) {
        return std::nullopt;
    }

    std::string secret(result);

    secret_password_free(result);

    return secret;
}


void store_secret(
    const std::string& account,
    const std::string& secret)
{
    GErrorPtr error;

    const gboolean success = secret_password_store_sync(
        &TOTP_SCHEMA,
        nullptr,                     // default collection
        (std::string(APPLICATION) + ": " + account).c_str(),
        secret.c_str(),
        nullptr,
        &error.ptr,
        "account",
        account.c_str(),
        nullptr
    );

    if (!success || error.ptr) {
        throw TotpError(
            std::string("Unable to store secret in desktop keyring: ") +
            (error.ptr ? error.ptr->message : "unknown error")
        );
    }
}


void delete_secret(const std::string& account)
{
    GErrorPtr error;

    const gboolean success = secret_password_clear_sync(
        &TOTP_SCHEMA,
        nullptr,
        &error.ptr,
        "account",
        account.c_str(),
        nullptr
    );

    if (error.ptr) {
        throw TotpError(
            std::string("Unable to delete secret from desktop keyring: ") +
            error.ptr->message
        );
    }

    if (!success) {
        throw TotpError(
            "No TOTP secret is stored for account '" +
            account + "'."
        );
    }
}


// ---------------------------------------------------------------------------
// Account index
// ---------------------------------------------------------------------------
//
// Secret Service doesn't give us a particularly convenient "list all
// accounts belonging to this application" operation through the simple
// password API.
//
// Therefore we keep a small index as another keyring item.
//
// IMPORTANT:
//
//     This contains account names only.
//     It never contains TOTP secrets.
// ---------------------------------------------------------------------------

std::vector<std::string> get_accounts()
{
    auto index = lookup_secret(INDEX_ACCOUNT);

    if (!index || index->empty()) {
        return {};
    }

    std::vector<std::string> result;

    std::stringstream stream(*index);
    std::string line;

    while (std::getline(stream, line)) {
        if (!line.empty()) {
            result.push_back(line);
        }
    }

    std::sort(result.begin(), result.end());

    result.erase(
        std::unique(result.begin(), result.end()),
        result.end()
    );

    return result;
}


void save_accounts(std::vector<std::string> accounts)
{
    std::sort(accounts.begin(), accounts.end());

    accounts.erase(
        std::unique(accounts.begin(), accounts.end()),
        accounts.end()
    );

    std::ostringstream stream;

    for (const auto& account : accounts) {
        stream << account << '\n';
    }

    store_secret(
        INDEX_ACCOUNT,
        stream.str()
    );
}


void add_account_to_index(const std::string& account)
{
    auto accounts = get_accounts();

    if (std::find(accounts.begin(), accounts.end(), account)
        == accounts.end()) {

        accounts.push_back(account);
        save_accounts(accounts);
    }
}


void remove_account_from_index(const std::string& account)
{
    auto accounts = get_accounts();

    accounts.erase(
        std::remove(
            accounts.begin(),
            accounts.end(),
            account
        ),
        accounts.end()
    );

    if (accounts.empty()) {
        // Remove the index item completely.
        try {
            delete_secret(INDEX_ACCOUNT);
        }
        catch (...) {
            // Nothing important to do if the index was already absent.
        }
    }
    else {
        save_accounts(accounts);
    }
}


// ---------------------------------------------------------------------------
// Base32
// ---------------------------------------------------------------------------

int base32_value(char c)
{
    c = static_cast<char>(
        std::toupper(static_cast<unsigned char>(c))
    );

    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }

    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }

    return -1;
}


std::vector<unsigned char> base32_decode(std::string input)
{
    // Accept spaces and hyphens when entering the secret.
    input.erase(
        std::remove_if(
            input.begin(),
            input.end(),
            [](unsigned char c) {
                return std::isspace(c) || c == '-';
            }
        ),
        input.end()
    );

    if (input.empty()) {
        throw TotpError("TOTP secret cannot be empty.");
    }

    std::vector<unsigned char> output;

    unsigned int buffer = 0;
    int bits = 0;

    for (char c : input) {

        if (c == '=') {
            break;
        }

        const int value = base32_value(c);

        if (value < 0) {
            throw TotpError(
                "Invalid Base32 character in TOTP secret."
            );
        }

        buffer = (buffer << 5) |
                 static_cast<unsigned int>(value);

        bits += 5;

        if (bits >= 8) {
            bits -= 8;

            output.push_back(
                static_cast<unsigned char>(
                    (buffer >> bits) & 0xff
                )
            );
        }
    }

    if (output.empty()) {
        throw TotpError(
            "TOTP secret does not contain any decoded data."
        );
    }

    return output;
}


// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------
//
// RFC 6238:
//
//     T = floor((current Unix time - T0) / X)
//
// Default:
//
//     T0 = 0
//     X  = 30 seconds
//     HMAC-SHA1
//     6 digits
// ---------------------------------------------------------------------------

struct TotpResult {
    std::string code;
    int remaining;
};


std::string calculate_totp(
    const std::vector<unsigned char>& key,
    std::uint64_t counter)
{
    std::array<unsigned char, 8> message{};

    for (int i = 7; i >= 0; --i) {
        message[i] =
            static_cast<unsigned char>(counter & 0xff);

        counter >>= 8;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;

    unsigned char* result = HMAC(
        EVP_sha1(),
        key.data(),
        static_cast<int>(key.size()),
        message.data(),
        message.size(),
        digest.data(),
        &digest_len
    );

    if (!result || digest_len < 20) {
        throw TotpError(
            "OpenSSL HMAC-SHA1 calculation failed."
        );
    }

    const int offset =
        digest[digest_len - 1] & 0x0f;

    const std::uint32_t binary =
        ((static_cast<std::uint32_t>(
            digest[offset]) & 0x7f) << 24) |
        ((static_cast<std::uint32_t>(
            digest[offset + 1]) & 0xff) << 16) |
        ((static_cast<std::uint32_t>(
            digest[offset + 2]) & 0xff) << 8) |
        (static_cast<std::uint32_t>(
            digest[offset + 3]) & 0xff);

    const std::uint32_t otp =
        binary % 1000000;

    std::ostringstream output;

    output
        << std::setw(TOTP_DIGITS)
        << std::setfill('0')
        << otp;

    return output.str();
}


TotpResult generate_totp(const std::string& secret)
{
    const auto key = base32_decode(secret);

    const auto now =
        std::chrono::system_clock::now();

    const auto seconds =
        std::chrono::duration_cast<
            std::chrono::seconds
        >(now.time_since_epoch()).count();

    if (seconds < 0) {
        throw TotpError("System clock is before Unix epoch.");
    }

    const std::uint64_t timestamp =
        static_cast<std::uint64_t>(seconds);

    const std::uint64_t counter =
        timestamp / TOTP_PERIOD;

    const int elapsed =
        static_cast<int>(timestamp % TOTP_PERIOD);

    const int remaining =
        TOTP_PERIOD - elapsed;

    return {
        calculate_totp(key, counter),
        remaining
    };
}


// ---------------------------------------------------------------------------
// Secure-ish terminal input
// ---------------------------------------------------------------------------

std::string read_secret()
{
    std::string secret;

    std::cout << "TOTP secret: ";
    std::cout.flush();

    // Disable terminal echo using the standard Unix utility.
    //
    // We deliberately avoid passing the secret through argv/environment.
    //
    // stty is standard on Debian.
    std::system("stty -echo");

    std::getline(std::cin, secret);

    std::system("stty echo");

    std::cout << '\n';

    if (!std::cin) {
        std::system("stty echo");
        throw TotpError("Unable to read TOTP secret.");
    }

    return secret;
}


// ---------------------------------------------------------------------------
// Validate secret
// ---------------------------------------------------------------------------

std::string validate_secret(const std::string& input)
{
    auto decoded = base32_decode(input);

    // Typical TOTP secrets are at least 80 bits.
    //
    // We don't enforce a minimum here because some services use
    // shorter secrets and pyotp accepts them too.
    if (decoded.empty()) {
        throw TotpError(
            "TOTP secret does not contain any decoded data."
        );
    }

    std::string normalized;

    for (char c : input) {
        if (std::isspace(
                static_cast<unsigned char>(c)) ||
            c == '-') {
            continue;
        }

        normalized.push_back(
            static_cast<char>(
                std::toupper(
                    static_cast<unsigned char>(c)
                )
            )
        );
    }

    return normalized;
}


// ---------------------------------------------------------------------------
// Get current code
// ---------------------------------------------------------------------------

TotpResult get_code(const std::string& account)
{
    const auto secret = lookup_secret(account);

    if (!secret) {
        throw TotpError(
            "No TOTP secret is stored for account '" +
            account +
            "'.\n"
            "Add it with: totp add " +
            account
        );
    }

    return generate_totp(*secret);
}


// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

void command_add(const std::string& raw_account)
{
    const auto account =
        normalize_account(raw_account);

    const auto existing =
        lookup_secret(account);

    if (existing) {
        std::cout
            << "Account '" << account
            << "' already exists. Replace it? [y/N] ";

        std::string answer;
        std::getline(std::cin, answer);

        std::transform(
            answer.begin(),
            answer.end(),
            answer.begin(),
            [](unsigned char c) {
                return static_cast<char>(
                    std::tolower(c)
                );
            }
        );

        if (answer != "y" && answer != "yes") {
            std::cout << "Not changed.\n";
            return;
        }
    }

    const std::string raw_secret =
        read_secret();

    const std::string secret =
        validate_secret(raw_secret);

    // Validate that the secret actually produces a TOTP.
    const auto test =
        generate_totp(secret);

    (void)test;

    store_secret(
        account,
        secret
    );

    add_account_to_index(account);

    // Clear local copies as best we can.
    std::string wiped = raw_secret;

    OPENSSL_cleanse(
        wiped.data(),
        wiped.size()
    );

    std::cout
        << "Account '" << account
        << "' added.\n";

    std::cout
        << "Current code: "
        << generate_totp(secret).code
        << '\n';
}


void command_remove(const std::string& raw_account)
{
    const auto account =
        normalize_account(raw_account);

    delete_secret(account);

    remove_account_from_index(account);

    std::cout
        << "Account '" << account
        << "' removed.\n";
}


void command_list()
{
    const auto accounts =
        get_accounts();

    if (accounts.empty()) {
        std::cout
            << "No TOTP accounts configured.\n\n"
            << "Add one with:\n"
            << "  totp add snappymail\n";

        return;
    }

    std::cout
        << "Configured TOTP accounts:\n\n";

    for (const auto& account : accounts) {

        try {
            const auto secret =
                lookup_secret(account);

            if (secret) {
                std::cout
                    << "  " << account << '\n';
            }
            else {
                std::cout
                    << "  " << account
                    << "  [missing secret]\n";
            }
        }
        catch (const TotpError& error) {
            std::cout
                << "  " << account
                << "  [keyring error]\n";
        }
    }
}


void command_get(
    const std::string& raw_account,
    bool watch,
    bool plain)
{
    const auto account =
        normalize_account(raw_account);

    if (!watch) {

        const auto result =
            get_code(account);

        if (plain) {
            std::cout
                << result.code
                << '\n';
        }
        else {
            std::cout
                << account
                << ": "
                << result.code
                << "  ("
                << result.remaining
                << "s remaining)\n";
        }

        return;
    }

    std::string previous_code;

    while (true) {

        const auto result =
            get_code(account);

        if (plain) {
            std::cout
                << '\r'
                << result.code
                << "       "
                << std::flush;
        }
        else {
            std::cout
                << '\r'
                << account
                << ": "
                << result.code
                << "  ("
                << std::setw(2)
                << result.remaining
                << "s remaining)"
                << std::flush;
        }

        std::this_thread::sleep_for(
            std::chrono::milliseconds(250)
        );
    }
}


// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

bool command_exists(const char* command)
{
    const std::string test =
        std::string("command -v ") +
        command +
        " >/dev/null 2>&1";

    return std::system(test.c_str()) == 0;
}


void copy_clipboard(const std::string& text)
{
    //
    // X11
    //
    if (const char* display = std::getenv("DISPLAY");
        display && *display) {

        if (!command_exists("xclip")) {
            throw TotpError(
                "X11 detected, but xclip is not installed.\n"
                "Install it with:\n"
                "  sudo apt install xclip"
            );
        }

        FILE* pipe = popen(
            "xclip -selection clipboard",
            "w"
        );

        if (!pipe) {
            throw TotpError(
                "Unable to start xclip."
            );
        }

        const size_t written = fwrite(
            text.data(),
            1,
            text.size(),
            pipe
        );

        const int result = pclose(pipe);

        if (written != text.size() || result != 0) {
            throw TotpError(
                "xclip failed."
            );
        }

        return;
    }


    //
    // Wayland
    //
    if (const char* wayland = std::getenv("WAYLAND_DISPLAY");
        wayland && *wayland) {

        if (!command_exists("wl-copy")) {
            throw TotpError(
                "Wayland detected, but wl-copy is not installed.\n"
                "Install it with:\n"
                "  sudo apt install wl-clipboard"
            );
        }

        FILE* pipe = popen(
            "wl-copy",
            "w"
        );

        if (!pipe) {
            throw TotpError(
                "Unable to start wl-copy."
            );
        }

        const size_t written = fwrite(
            text.data(),
            1,
            text.size(),
            pipe
        );

        const int result = pclose(pipe);

        if (written != text.size() || result != 0) {
            throw TotpError(
                "wl-copy failed."
            );
        }

        return;
    }


    throw TotpError(
        "Unable to determine the graphical clipboard environment.\n"
        "Neither X11 ($DISPLAY) nor Wayland ($WAYLAND_DISPLAY) "
        "is available."
    );
}


void clear_clipboard()
{
    //
    // X11
    //
    if (const char* display = std::getenv("DISPLAY");
        display && *display) {

        if (command_exists("xclip")) {
            std::system(
                "xclip -selection clipboard "
                "-i /dev/null >/dev/null 2>&1"
            );
        }

        return;
    }


    //
    // Wayland
    //
    if (const char* wayland = std::getenv("WAYLAND_DISPLAY");
        wayland && *wayland) {

        if (command_exists("wl-copy")) {
            std::system(
                "wl-copy --clear >/dev/null 2>&1"
            );
        }

        return;
    }
}


void command_copy(
    const std::string& raw_account,
    int seconds)
{
    const auto account =
        normalize_account(raw_account);

    const auto result =
        get_code(account);

    copy_clipboard(result.code);

    std::cout
        << "TOTP code copied to clipboard.\n";

    std::cout
        << "Clipboard will be cleared in "
        << seconds
        << " seconds.\n";

    std::this_thread::sleep_for(
        std::chrono::seconds(seconds)
    );

    clear_clipboard();

    std::cout
        << "Clipboard cleared.\n";
}


// ---------------------------------------------------------------------------
// Keyring test
// ---------------------------------------------------------------------------

void command_test()
{
    constexpr const char* TEST_ACCOUNT =
        "__totp_keyring_test__";

    constexpr const char* TEST_SECRET =
        "totp-cli-test";

    store_secret(
        TEST_ACCOUNT,
        TEST_SECRET
    );

    const auto result =
        lookup_secret(TEST_ACCOUNT);

    if (!result || *result != TEST_SECRET) {

        try {
            delete_secret(TEST_ACCOUNT);
        }
        catch (...) {}

        throw TotpError(
            "Desktop keyring test failed: "
            "value could not be read back."
        );
    }

    delete_secret(TEST_ACCOUNT);

    std::cout
        << "Desktop keyring: OK\n";
}


// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

void print_help()
{
    std::cout << R"(totp - local TOTP authenticator

Usage:

  totp add ACCOUNT
      Add or replace a TOTP account.

  totp ACCOUNT
      Generate the current TOTP code.

  totp get ACCOUNT
      Same as "totp ACCOUNT".

  totp ACCOUNT --watch
      Continuously display the current code.

  totp ACCOUNT --plain
      Print only the six-digit code.

  totp copy ACCOUNT
      Copy the current code to the clipboard and clear it
      automatically after 20 seconds.

  totp copy ACCOUNT --seconds N
      Use a custom clipboard timeout.

  totp list
      List configured accounts.

  totp remove ACCOUNT
      Remove an account and its secret from the keyring.

  totp test
      Test access to the desktop Secret Service keyring.

  totp --help
      Show this help.

Examples:

  totp add snappymail

  totp snappymail

  totp snappymail --watch

  totp snappymail --plain

  totp copy snappymail

  totp list

  totp remove snappymail
)";
}


// ---------------------------------------------------------------------------
// Argument handling
// ---------------------------------------------------------------------------

bool is_command(const std::string& value)
{
    return
        value == "add" ||
        value == "remove" ||
        value == "list" ||
        value == "test" ||
        value == "get" ||
        value == "copy" ||
        value == "--help" ||
        value == "-h";
}


int run(int argc, char* argv[])
{
    if (argc < 2) {
        print_help();
        return 1;
    }

    std::vector<std::string> args;

    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }


    if (args[0] == "--help" ||
        args[0] == "-h") {

        print_help();
        return 0;
    }


    //
    // Shorthand:
    //
    //     totp snappymail
    //
    // becomes:
    //
    //     totp get snappymail
    //
    if (!is_command(args[0])) {

        std::string account =
            args[0];

        bool watch = false;
        bool plain = false;

        for (std::size_t i = 1;
             i < args.size();
             ++i) {

            if (args[i] == "--watch") {
                watch = true;
            }
            else if (args[i] == "--plain") {
                plain = true;
            }
            else {
                throw TotpError(
                    "Unknown option: " +
                    args[i]
                );
            }
        }

        command_get(
            account,
            watch,
            plain
        );

        return 0;
    }


    const std::string& command =
        args[0];


    // -----------------------------------------------------------------------
    // add
    // -----------------------------------------------------------------------

    if (command == "add") {

        if (args.size() != 2) {
            throw TotpError(
                "Usage: totp add ACCOUNT"
            );
        }

        command_add(args[1]);

        return 0;
    }


    // -----------------------------------------------------------------------
    // remove
    // -----------------------------------------------------------------------

    if (command == "remove") {

        if (args.size() != 2) {
            throw TotpError(
                "Usage: totp remove ACCOUNT"
            );
        }

        command_remove(args[1]);

        return 0;
    }


    // -----------------------------------------------------------------------
    // list
    // -----------------------------------------------------------------------

    if (command == "list") {

        if (args.size() != 1) {
            throw TotpError(
                "Usage: totp list"
            );
        }

        command_list();

        return 0;
    }


    // -----------------------------------------------------------------------
    // test
    // -----------------------------------------------------------------------

    if (command == "test") {

        if (args.size() != 1) {
            throw TotpError(
                "Usage: totp test"
            );
        }

        command_test();

        return 0;
    }


    // -----------------------------------------------------------------------
    // get
    // -----------------------------------------------------------------------

    if (command == "get") {

        if (args.size() < 2) {
            throw TotpError(
                "Usage: totp get ACCOUNT [--watch] [--plain]"
            );
        }

        bool watch = false;
        bool plain = false;

        for (std::size_t i = 2;
             i < args.size();
             ++i) {

            if (args[i] == "--watch") {
                watch = true;
            }
            else if (args[i] == "--plain") {
                plain = true;
            }
            else {
                throw TotpError(
                    "Unknown option: " +
                    args[i]
                );
            }
        }

        command_get(
            args[1],
            watch,
            plain
        );

        return 0;
    }


    // -----------------------------------------------------------------------
    // copy
    // -----------------------------------------------------------------------

    if (command == "copy") {

        if (args.size() < 2) {
            throw TotpError(
                "Usage: totp copy ACCOUNT [--seconds N]"
            );
        }

        int seconds = 20;

        for (std::size_t i = 2;
             i < args.size();
             ++i) {

            if (args[i] == "--seconds") {

                if (i + 1 >= args.size()) {
                    throw TotpError(
                        "--seconds requires a value."
                    );
                }

                try {
                    seconds =
                        std::stoi(args[++i]);
                }
                catch (...) {
                    throw TotpError(
                        "Invalid --seconds value."
                    );
                }

                if (seconds <= 0 ||
                    seconds > 3600) {

                    throw TotpError(
                        "--seconds must be between "
                        "1 and 3600."
                    );
                }
            }
            else {
                throw TotpError(
                    "Unknown option: " +
                    args[i]
                );
            }
        }

        command_copy(
            args[1],
            seconds
        );

        return 0;
    }


    throw TotpError(
        "Unknown command: " + command
    );
}

} // namespace


int main(int argc, char* argv[])
{
    try {
        return run(argc, argv);
    }
    catch (const TotpError& error) {

        std::cerr
            << "Error: "
            << error.what()
            << '\n';

        return 1;
    }
    catch (const std::exception& error) {

        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
