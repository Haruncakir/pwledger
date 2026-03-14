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

#ifndef PWLEDGER_CLI_ENTRY_OPS_H
#define PWLEDGER_CLI_ENTRY_OPS_H

#include <pwledger/PrimaryTable.h>
#include <pwledger/SecretEntry.h>
#include <pwledger/uuid.h>

#include <string>

namespace pwledger {

using Uuid = pwledger::Uuid;

// CRUD operations on PrimaryTable entries.
// Return values follow a consistent pattern:
//   - create / update: bool (true on success, false on conflict or not-found)
//   - read:            const SecretEntry* (nullptr if not found)
//   - delete:          bool (true if removed, false if not found)
// Programmer misuse (empty UUID) throws std::invalid_argument.

bool entry_create(PrimaryTable& table, const Uuid& uuid, std::string primary_key, std::string username_or_email);
const SecretEntry* entry_read(const PrimaryTable& table, const Uuid& uuid);
bool entry_update_secret(PrimaryTable& table, const Uuid& uuid);
bool entry_delete(PrimaryTable& table, const Uuid& uuid);

// Updates the last_used_at timestamp for the entry with the given UUID.
bool touch_last_used(PrimaryTable& table, const Uuid& uuid);

}  // namespace pwledger

#endif  // PWLEDGER_CLI_ENTRY_OPS_H
