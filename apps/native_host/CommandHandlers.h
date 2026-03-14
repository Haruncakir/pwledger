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

#ifndef PWLEDGER_HOST_COMMAND_HANDLERS_H
#define PWLEDGER_HOST_COMMAND_HANDLERS_H

#include <pwledger/Config.h>
#include <pwledger/PrimaryTable.h>

#include <optional>

#include <nlohmann/json.hpp>

namespace pwledger {

// VaultState is the authoritative lock status for the session.
enum class VaultState {
  Locked,
  Unlocked,
};

[[nodiscard]] nlohmann::json handle_ping(const nlohmann::json& req,
                                         VaultState state,
                                         PrimaryTable& table,
                                         std::optional<nlohmann::json> id);

[[nodiscard]] nlohmann::json handle_unlock(const nlohmann::json& req,
                                            VaultState& state,
                                            PrimaryTable& table,
                                            const Config& cfg,
                                            std::optional<nlohmann::json> id);

[[nodiscard]] nlohmann::json handle_lock(const nlohmann::json& req,
                                          VaultState& state,
                                          PrimaryTable& table,
                                          std::optional<nlohmann::json> id);

[[nodiscard]] nlohmann::json handle_init_vault(const nlohmann::json& req,
                                                VaultState& state,
                                                PrimaryTable& table,
                                                const Config& cfg,
                                                std::optional<nlohmann::json> id);

[[nodiscard]] nlohmann::json handle_search(const nlohmann::json& req,
                                            const PrimaryTable& table,
                                            std::optional<nlohmann::json> id);

[[nodiscard]] nlohmann::json handle_copy(const nlohmann::json& req,
                                          PrimaryTable& table,
                                          std::optional<nlohmann::json> id);

[[nodiscard]] nlohmann::json handle_clip_clear(const nlohmann::json& req,
                                                std::optional<nlohmann::json> id);

}  // namespace pwledger

#endif  // PWLEDGER_HOST_COMMAND_HANDLERS_H
