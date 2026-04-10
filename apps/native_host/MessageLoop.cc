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

#include "MessageLoop.h"
#include "CommandHandlers.h"
#include "NativeMessaging.h"
#include "ResponseHelpers.h"

#include <pwledger/PrimaryTable.h>

#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace pwledger {

// ============================================================================
// Dispatch table
// ============================================================================
//
// Each entry names a command, whether it requires an unlocked vault, and a
// handler. The requires_unlock flag is checked centrally in the message loop
// before invoking the handler, so individual handlers do not need to recheck
// it. Adding a new command requires a conscious decision about auth posture.

// Handler signature is intentionally wide to accommodate all commands
// without overloading. Unused parameters are named with /**/ in handlers.
using Handler = json (*)(const json&, VaultState&, PrimaryTable&, const Config&, std::optional<json>);

struct CommandDescriptor {
  bool requires_unlock;
  Handler handle;
};

// Trampoline adapters bridge the uniform dispatch signature to the narrower
// per-handler signatures, keeping the handler implementations clean.
namespace {

json dispatch_ping(const json& req, VaultState& state,
                   PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_ping(req, state, table, std::move(id));
}
json dispatch_unlock(const json& req, VaultState& state,
                     PrimaryTable& table, const Config& cfg, std::optional<json> id) {
  return handle_unlock(req, state, table, cfg, std::move(id));
}
json dispatch_lock(const json& req, VaultState& state,
                   PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_lock(req, state, table, std::move(id));
}
json dispatch_init_vault(const json& req, VaultState& state,
                         PrimaryTable& table, const Config& cfg, std::optional<json> id) {
  return handle_init_vault(req, state, table, cfg, std::move(id));
}
json dispatch_search(const json& req, VaultState& /*state*/,
                     PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_search(req, table, std::move(id));
}
json dispatch_copy(const json& req, VaultState& /*state*/,
                   PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_copy(req, table, std::move(id));
}
json dispatch_clip_clear(const json& req, VaultState& /*state*/,
                         PrimaryTable& /*table*/, const Config& /*cfg*/, std::optional<json> id) {
  return handle_clip_clear(req, std::move(id));
}
json dispatch_get_credentials(const json& req, VaultState& /*state*/,
                              PrimaryTable& table, const Config& /*cfg*/, std::optional<json> id) {
  return handle_get_credentials(req, table, std::move(id));
}

}  // anonymous namespace

const std::unordered_map<std::string, CommandDescriptor> kCommands{
  { "ping",              { /*requires_unlock=*/false, dispatch_ping              } },
  { "unlock",            { /*requires_unlock=*/false, dispatch_unlock            } },
  { "lock",              { /*requires_unlock=*/false, dispatch_lock              } },
  { "init_vault",        { /*requires_unlock=*/false, dispatch_init_vault        } },
  { "search",            { /*requires_unlock=*/true,  dispatch_search            } },
  { "copy",              { /*requires_unlock=*/true,  dispatch_copy              } },
  { "clip_clear",        { /*requires_unlock=*/false, dispatch_clip_clear        } },
  { "get_credentials",   { /*requires_unlock=*/true,  dispatch_get_credentials   } },
};

// ============================================================================
// Message loop
// ============================================================================

void run_message_loop(const Config& cfg) {
  PrimaryTable table;
  VaultState   state = VaultState::Locked;

  for (;;) {
    auto raw = read_message();
    if (!raw.has_value()) {
      break;  // EOF, I/O error, or oversized message; terminate cleanly
    }

    // Extract the request ID early so it can be echoed in every response,
    // including parse-error responses.
    std::optional<json> req_id;
    json response;

    try {
      json req = json::parse(*raw);

      if (req.contains("id")) {
        req_id = req["id"];
      }

      const std::string cmd = req.value("command", "");
      const auto it = kCommands.find(cmd);

      if (it == kCommands.end()) {
        response = make_error("Unknown command", req_id);
      } else if (it->second.requires_unlock && state != VaultState::Unlocked) {
        response = make_error("Locked", req_id);
      } else {
        response = it->second.handle(req, state, table, cfg, req_id);
      }
    } catch (const json::parse_error&) {
      response = make_error("Invalid JSON", req_id);
    } catch (const std::exception& e) {
      std::cerr << "Warning: unhandled exception in command handler: "
                << e.what() << '\n';
      response = make_error("Internal error", req_id);
    }

    write_message(response);
  }
}

}  // namespace pwledger
