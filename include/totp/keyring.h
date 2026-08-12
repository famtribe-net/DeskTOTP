#pragma once

#include <string>
#include <vector>

namespace keyring {

std::string get(const std::string &account);
void put(const std::string &account, const std::string &secret);
void remove(const std::string &account);
bool exists(const std::string &account);

std::vector<std::string> accounts();

} // namespace keyring
