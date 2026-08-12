#include <totp/keyring.h>

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <glib.h>
#include <libsecret/secret.h>

namespace keyring {
namespace {

constexpr const char* APPLICATION = "totp-cli";
constexpr const char* SCHEMA_NAME = "net.famtribe.totp";
constexpr const char* INDEX = "__accounts__";

SecretSchema make_schema()
{
    SecretSchema schema{};
    schema.name = SCHEMA_NAME;
    schema.flags = SECRET_SCHEMA_NONE;
    schema.attributes[0].name = "account";
    schema.attributes[0].type = SECRET_SCHEMA_ATTRIBUTE_STRING;
    return schema;
}

const SecretSchema SCHEMA = make_schema();

std::string lookup(const std::string& account)
{
    GError* error = nullptr;

    gchar* value = secret_password_lookup_sync(
        &SCHEMA, nullptr, &error,
        "account", account.c_str(), nullptr
    );

    if (error) {
        std::string message = error->message;
        g_error_free(error);
        throw std::runtime_error(
            "Unable to access desktop keyring: " + message
        );
    }

    if (!value)
        return {};

    std::string result(value);
    secret_password_free(value);
    return result;
}

void store(const std::string& account, const std::string& secret)
{
    GError* error = nullptr;

    const gboolean ok = secret_password_store_sync(
        &SCHEMA,
        nullptr,
        (std::string(APPLICATION) + ": " + account).c_str(),
        secret.c_str(),
        nullptr,
        &error,
        "account", account.c_str(),
        nullptr
    );

    if (!ok || error) {
        std::string message =
            error ? error->message : "unknown error";
        if (error)
            g_error_free(error);
        throw std::runtime_error(
            "Unable to store secret in desktop keyring: " + message
        );
    }
}

std::vector<std::string> read_accounts()
{
    const std::string raw = lookup(INDEX);
    if (raw.empty())
        return {};

    std::vector<std::string> result;
    std::stringstream ss(raw);
    std::string line;

    while (std::getline(ss, line)) {
        if (!line.empty())
            result.push_back(line);
    }

    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

void write_accounts(std::vector<std::string> list)
{
    std::sort(list.begin(), list.end());
    list.erase(std::unique(list.begin(), list.end()), list.end());

    std::ostringstream out;
    for (const auto& account : list)
        out << account << '\n';

    store(INDEX, out.str());
}

} // namespace

std::string get(const std::string& account)
{
    return lookup(account);
}

bool exists(const std::string& account)
{
    return !lookup(account).empty();
}

void put(const std::string& account, const std::string& secret)
{
    store(account, secret);

    auto list = read_accounts();
    if (std::find(list.begin(), list.end(), account) == list.end()) {
        list.push_back(account);
        write_accounts(std::move(list));
    }
}

void remove(const std::string& account)
{
    GError* error = nullptr;

    const gboolean ok = secret_password_clear_sync(
        &SCHEMA, nullptr, &error,
        "account", account.c_str(), nullptr
    );

    if (error) {
        std::string message = error->message;
        g_error_free(error);
        throw std::runtime_error(
            "Unable to access desktop keyring: " + message
        );
    }

    if (!ok)
        throw std::runtime_error(
            "No TOTP secret is stored for account '" + account + "'."
        );

    auto list = read_accounts();
    list.erase(std::remove(list.begin(), list.end(), account), list.end());

    if (list.empty()) {
        // Keep an empty index out of the keyring.
        GError* clear_error = nullptr;
        secret_password_clear_sync(
            &SCHEMA, nullptr, &clear_error,
            "account", INDEX, nullptr
        );
        if (clear_error)
            g_error_free(clear_error);
    } else {
        write_accounts(std::move(list));
    }
}

std::vector<std::string> accounts()
{
    return read_accounts();
}

} // namespace keyring
