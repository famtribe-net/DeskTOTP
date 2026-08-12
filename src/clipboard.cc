#include <totp/clipboard.h>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace clipboard {
namespace {

bool command_exists(const char* command)
{
    return std::system(
        (std::string("command -v ") + command +
         " >/dev/null 2>&1").c_str()
    ) == 0;
}

bool has_env(const char* name)
{
    const char* value = std::getenv(name);
    return value && *value;
}

void pipe_text(const char* command, const std::string& text)
{
    FILE* pipe = popen(command, "w");
    if (!pipe)
        throw std::runtime_error("Unable to start clipboard command.");

    const std::size_t written =
        std::fwrite(text.data(), 1, text.size(), pipe);
    const int status = pclose(pipe);

    if (written != text.size() || status != 0)
        throw std::runtime_error("Clipboard command failed.");
}

} // namespace

void copy(const std::string& text)
{
    // Prefer the actual session type, not merely whether an executable exists.
    if (has_env("DISPLAY")) {
        if (!command_exists("xclip"))
            throw std::runtime_error(
                "X11 detected, but xclip is not installed. "
                "Install it with: sudo apt install xclip"
            );

        pipe_text("xclip -selection clipboard", text);
        return;
    }

    if (has_env("WAYLAND_DISPLAY")) {
        if (!command_exists("wl-copy"))
            throw std::runtime_error(
                "Wayland detected, but wl-copy is not installed. "
                "Install it with: sudo apt install wl-clipboard"
            );

        pipe_text("wl-copy", text);
        return;
    }

    throw std::runtime_error(
        "Neither X11 ($DISPLAY) nor Wayland ($WAYLAND_DISPLAY) is available."
    );
}

void clear()
{
    if (has_env("DISPLAY") && command_exists("xclip")) {
        std::system(
            "xclip -selection clipboard -i /dev/null "
            ">/dev/null 2>&1"
        );
        return;
    }

    if (has_env("WAYLAND_DISPLAY") && command_exists("wl-copy")) {
        std::system("wl-copy --clear >/dev/null 2>&1");
    }
}

} // namespace clipboard
