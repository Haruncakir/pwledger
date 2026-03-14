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

#include "CommandLoop.h"
#include "Display.h"
#include "EntryOps.h"
#include "SecretIO.h"

#include <pwledger/Clipboard.h>
#include <pwledger/Secret.h>
#include <pwledger/uuid.h>

#include <cstring>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>

namespace pwledger {

// Convenience alias used throughout this file.
using Uuid = pwledger::Uuid;

// ============================================================================
// Command handlers
// ============================================================================
//
// Each command is a free function that reads its arguments from stdin
// interactively and delegates to the appropriate CRUD or clipboard function.
// All command functions share the signature  void (*)(AppState&)  so they
// can be stored uniformly in the dispatch table.
//
// Exceptions thrown by CRUD operations are caught in run_command_loop and
// reported to the user without terminating the session.

// ----------------------------------------------------------------------------
// parse_uuid_input
// ----------------------------------------------------------------------------
// Reads a UUID string from stdin and parses it into a Uuid. Returns
// std::nullopt and prints an error if the input is not a valid UUID.
std::optional<Uuid> parse_uuid_input() {
  std::string input;
  std::cout << "UUID: ";
  std::getline(std::cin, input);

  auto uuid = Uuid::from_string(input);
  if (!uuid) {
    std::cout << "Error: '" << input << "' is not a valid UUID.\n";
  }
  return uuid;
}

void cmd_add(AppState& state) {
  std::string key, user;
  std::cout << "Primary key   : ";
  std::getline(std::cin, key);
  std::cout << "Username/email: ";
  std::getline(std::cin, user);

  // Auto-generate a UUID-v4 for the new entry.
  Uuid uuid = Uuid::generate();

  if (entry_create(state.table, uuid, std::move(key), std::move(user))) {
    std::cout << "Entry added (UUID: " << uuid << ").\n";
    save_vault_safe(state);
  } else {
    std::cout << "Error: UUID collision (astronomically unlikely).\n";
  }
}

void cmd_get(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  const SecretEntry* entry = entry_read(state.table, *uuid);
  if (!entry) {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
    return;
  }
  if (touch_last_used(state.table, *uuid)) {
    save_vault_safe(state);
  }
  print_entry(*uuid, *entry);
}

void cmd_update(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  if (entry_update_secret(state.table, *uuid)) {
    std::cout << "Secret updated.\n";
    save_vault_safe(state);
  } else {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
  }
}

void cmd_delete(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  if (state.config.cli.confirm_before_delete) {
    std::cout << "Delete entry '" << *uuid << "'? [y/N]: ";
    std::string confirm;
    std::getline(std::cin, confirm);
    if (confirm != "y" && confirm != "Y") {
      std::cout << "Cancelled.\n";
      return;
    }
  }

  if (entry_delete(state.table, *uuid)) {
    std::cout << "Entry deleted.\n";
    save_vault_safe(state);
  } else {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
  }
}

void cmd_list(AppState& state) {
  print_table(state.table);
}

void cmd_copy(AppState& state) {
  auto uuid = parse_uuid_input();
  if (!uuid) {
    return;
  }

  const SecretEntry* entry = entry_read(state.table, *uuid);
  if (!entry) {
    std::cout << "Error: no entry found for UUID '" << *uuid << "'.\n";
    return;
  }
  if (touch_last_used(state.table, *uuid)) {
    save_vault_safe(state);
  }
  entry->plaintext_secret.with_read_access([&](std::span<const char> buf) {
    clipboard_write(std::string_view(buf.data(), ::strnlen(buf.data(), buf.size())));
  });
}

void cmd_clip_clear(AppState& /*state*/) {
  clipboard_clear();
}

void cmd_save(AppState& state) {
  save_vault_safe(state);
  std::cout << "Vault saved to " << state.vault_path << ".\n";
}

void cmd_change_master(AppState& state) {
  Secret new_password(256);
  prompt_secret("Enter new master password", new_password, 256, /*confirm=*/true);
  state.master_password = std::move(new_password);
  save_vault_safe(state);
  std::cout << "Master password changed and vault re-encrypted.\n";
}

void cmd_help(AppState& /*state*/) {
  std::cout << "Commands:\n"
            << "  add            Add a new entry\n"
            << "  get            Show an entry\n"
            << "  update         Update the secret for an entry\n"
            << "  delete         Delete an entry\n"
            << "  list           List all entries\n"
            << "  copy           Copy an entry's secret to the clipboard\n"
            << "  clip-clear     Clear the clipboard\n"
            << "  save           Force save the vault to disk\n"
            << "  change-master  Change the vault master password\n"
            << "  help           Show this message\n"
            << "  quit           Exit\n";
}

// ----------------------------------------------------------------------------
// run_command_loop
// ----------------------------------------------------------------------------
// Reads command names from stdin and dispatches to the appropriate handler
// until the user types "quit" or stdin is exhausted (EOF). Exceptions from
// command handlers are caught and reported without terminating the session.
// Commands taking AppState can mutate the table and auto-save.
void run_command_loop(AppState& state) {
  using CommandFn = void (*)(AppState&);

  const std::unordered_map<std::string, CommandFn> dispatch{
      {"add", cmd_add},
      {"get", cmd_get},
      {"update", cmd_update},
      {"delete", cmd_delete},
      {"list", cmd_list},
      {"copy", cmd_copy},
      {"clip-clear", cmd_clip_clear},
      {"save", cmd_save},
      {"change-master", cmd_change_master},
      {"help", cmd_help},
  };

  std::cout << "pwledger — type 'help' for available commands.\n";

  std::string line;
  for (;;) {
    std::cout << "\npwledger> ";
    std::cout.flush();

    if (!std::getline(std::cin, line)) {
      break;  // EOF (Ctrl-D / Ctrl-Z)
    }

    // Trim leading and trailing whitespace.
    const auto first = line.find_first_not_of(" \t\r\n");
    const auto last = line.find_last_not_of(" \t\r\n");
    if (first == std::string::npos) {
      continue;
    }
    const std::string cmd = line.substr(first, last - first + 1);

    if (cmd == "quit" || cmd == "exit") {
      break;
    }

    const auto it = dispatch.find(cmd);
    if (it == dispatch.end()) {
      std::cout << "Unknown command '" << cmd << "'. Type 'help'.\n";
      continue;
    }

    try {
      it->second(state);
    } catch (const std::exception& e) {
      std::cout << "Error: " << e.what() << '\n';
    }
  }

  std::cout << "\nGoodbye.\n";
}

}  // namespace pwledger
