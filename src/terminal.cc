#include <totp/terminal.h>

#include <cerrno>
#include <iostream>
#include <stdexcept>
#include <termios.h>
#include <unistd.h>

namespace terminal {
namespace {

class EchoGuard {
public:
    EchoGuard()
    {
        if (tcgetattr(STDIN_FILENO, &original_) != 0)
            throw std::runtime_error("Unable to read terminal settings.");

        termios hidden = original_;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);

        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0)
            throw std::runtime_error("Unable to disable terminal echo.");

        active_ = true;
    }

    ~EchoGuard()
    {
        if (active_)
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
    }

    EchoGuard(const EchoGuard&) = delete;
    EchoGuard& operator=(const EchoGuard&) = delete;

private:
    termios original_{};
    bool active_ = false;
};

} // namespace

std::string read_hidden(const std::string& prompt)
{
    if (!isatty(STDIN_FILENO))
        throw std::runtime_error(
            "Secret input requires an interactive terminal."
        );

    std::cout << prompt << std::flush;
    EchoGuard guard;

    std::string value;
    if (!std::getline(std::cin, value))
        throw std::runtime_error("Unable to read secret.");

    std::cout << '\n';
    return value;
}

} // namespace terminal
