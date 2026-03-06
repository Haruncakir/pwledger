/* Copyright (c) 2026 Harun
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <pwledger/Clipboard.h>
#include <pwledger/PrimaryTable.h>
#include <pwledger/ProcessHardening.h>
#include <pwledger/Secret.h>
#include <pwledger/VaultIO.h>
#include <pwledger/VaultPath.h>

#include <cstdint>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

using json = nlohmann::json;

// Native Messaging Protocol read/write
std::string read_message() {
  uint32_t length = 0;
  if (!std::cin.read(reinterpret_cast<char*>(&length), sizeof(length))) {
    return "";
  }
  std::string message(length, '\0');
  if (!std::cin.read(&message[0], length)) {
    return "";
  }
  return message;
}

void write_message(const json& msg) {
  std::string s = msg.dump();
  uint32_t length = static_cast<uint32_t>(s.length());
  std::cout.write(reinterpret_cast<const char*>(&length), sizeof(length));
  std::cout << s;
  std::cout.flush();
}

int main() {
  // Apply the same process hardening as the CLI before touching any secrets.
  pwledger::harden_process();

  // sodium_init must be called once before any Secret is constructed.
  if (sodium_init() < 0) {
    return 1;
  }

#ifdef _WIN32
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  pwledger::PrimaryTable table;
  bool is_unlocked = false;

  while (true) {
    std::string msg_str = read_message();
    if (msg_str.empty()) {
      break;  // EOF or error
    }

    try {
      json req = json::parse(msg_str);
      std::string cmd = req.value("command", "");
      json response = {{"status", "error"}, {"message", "Unknown command"}};

      if (req.contains("id")) {
        response["id"] = req["id"];
      }

      if (cmd == "ping") {
        response["status"] = "ok";
        response["is_unlocked"] = is_unlocked;
      } else if (cmd == "unlock") {
        std::string password = req.value("password", "");
        auto vault_path = pwledger::default_vault_path();
        if (pwledger::VaultIO::vault_exists(vault_path)) {
          try {
            table = pwledger::VaultIO::load_vault(vault_path, password);
            is_unlocked = true;
            response["status"] = "ok";
            // Clean up password from memory since json object string can't be well-protected,
            // but std::string short lifetime and nlohmann json's short lifetime reduces risk.
          } catch (const std::exception& e) {
            response["status"] = "error";
            response["message"] = e.what();
          }
        } else {
          response["status"] = "error";
          response["message"] = "Vault not found";
        }
      } else if (cmd == "lock") {
        table.clear();
        is_unlocked = false;
        response["status"] = "ok";
      } else if (cmd == "search") {
        if (!is_unlocked) {
          response["status"] = "error";
          response["message"] = "Locked";
        } else {
          std::string query = req.value("query", "");
          json results = json::array();
          for (const auto& [uuid, entry] : table) {
            if (query.empty() || entry.primary_key.find(query) != std::string::npos ||
                entry.username_or_email.find(query) != std::string::npos) {
              json item = {{"uuid", uuid.to_string()},
                           {"primary_key", entry.primary_key},
                           {"username", entry.username_or_email}};
              results.push_back(item);
            }
          }
          response["status"] = "ok";
          response["results"] = results;
        }
      } else if (cmd == "copy") {
        if (!is_unlocked) {
          response["status"] = "error";
          response["message"] = "Locked";
        } else {
          std::string uuid_str = req.value("uuid", "");
          auto uuid = pwledger::Uuid::from_string(uuid_str);
          if (uuid) {
            auto it = table.find(*uuid);
            if (it != table.end()) {
              // Extract secret using access guard and apply to clipboard avoiding std::cout.
              it->second.plaintext_secret.with_read_access([](std::span<const char> buf) {
                std::size_t len = ::strnlen(buf.data(), buf.size());
                pwledger::detail::clipboard_write(std::string_view(buf.data(), len));
              });
              
              it->second.metadata.last_used_at = std::chrono::system_clock::now();
              response["status"] = "ok";
            } else {
              response["status"] = "error";
              response["message"] = "Not found";
            }
          } else {
            response["status"] = "error";
            response["message"] = "Invalid UUID";
          }
        }
      }

      write_message(response);
    } catch (const json::parse_error& e) {
      write_message({{"status", "error"}, {"message", "Invalid JSON"}});
    }
  }

  return 0;
}
