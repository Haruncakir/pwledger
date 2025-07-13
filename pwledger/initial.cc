// auto password generator
// portable accross devices via USB; idk if it makes sense;
//   no-cloud based solution, never...
// more like a digital vault
// password age - strength score
// dark-web monitoring - might be overkill in the beginning
// master password
// browser extension
// windows and linux

#include <iostream>
#include <string>

#include "SecureString.h"
#include "TerminalManager.h"

[[maybe_unused]]
static void menu() {
  std::cout << "PWLEDGER MENU\n";
  std::cout << "=============================\n";
  std::cout << "1- Store a password\n";
  std::cout << "2- Get a password\n";  // CRUD
}

static pwledger::secure_string readPassword(const std::string &prompt = "Enter password: ") {
  std::cout << prompt;
  std::cout.flush();

  pwledger::TerminalManager tm;

  if (!tm.isConfigured()) {
    std::cerr << "Warning: Secure input may not be available" << std::endl;
  }

  pwledger::secure_string password;
  char ch{};

  while (true) {
    ch = static_cast<char>(std::cin.get());

    if (ch == '\n' || ch == '\r') {
      break;                               // enter key pressed
    } else if (ch == '\b' || ch == 127) {  // backspace
      if (!password.empty()) {
        password.pop_back();
        std::cout << "\b \b";  // erase character visually
      }
    } else if (ch >= 32 && ch <= 126) {  // printable characters
      password += ch;
      std::cout << '*';  // display asterisk for feedback
    }
    std::cout.flush();
  }

  std::cout << std::endl;
  return password;
}

void storePassword() {
  // most standard input functions store the typed characters
  // in regular memory buffers, which means the the password might
  // be copied multiple times before we even begin processing it.
  // for secure memory buffer:
  // look at sodium_mprotect_* family of functions

  // REMEMBER: if something fails e.g. encrypion, allocation...
  // what if user cancels the operation partway through?
  // handle in a way that doesn't leave sensitive data exposed
  // ensure that all sensitive memory is immediatly cleared
  // before returning control to the calling function
  // minimize the time between password input and encrpytion.

  // STEP 1
  // TODO: implement a custom input routine that disables echo to
  // the terminal
  // UNIX: tcgetattr() and tcsetattr()
  // Windows: SetConsoloMode()
  auto password = readPassword();
  // TODO: ASCII vs UTF-8 (or UTF family) any issue arise?
  // SEARCH: can user provide suspicious password ?

  // STEP 2
  // TODO: perform validation on password (if necessary)

  // STEP 3
  // TODO: before encrypt the password, generate the
  // cryptographic parameters that will make each password uniqiue
  // - generate unique salt for this password entry
  //   (randombytes_buf() from libsodium)
  //   (16-32 bytes to prevent rainbow table attacks)
  //   (store this salt separately from the encrypted password)
  // - for KDF: crypto_pwhash() from libsodium to
  //   generate encryption keys from a master password

  // STEP 4
  // TODO: encrypt password with its salt
  // crypto_secretbox_easy() from libsodium
  // should happen from one secure input buffer to another
  // then immediately clear with sodium_memzero()

  // STEP 5
  // store it in hash map structure

  // STEP 6
  // comprehensive memory clean up and verification
}

/*
Enhanced Password Manager Data Structure
============================================

Enhanced Structure with Security & Features:
=====================================================================================================
| Entry ID | Primary Key/URL                  | Username/Email    | Encrypted Password | Salt       |
|----------|----------------------------------|-------------------|--------------------|------------|
| 001      | https://www.example.com/login    | john@email.com    | 8x9A2mKp...        | r4nD0mS4lt |
| 002      | https://www.another_example.com/ | johndoe           | 3kL9xZ1q...        | aB3dF6gH9j |
| 003      | Banking:Chase_Checking           | john.doe          | 9mN2bV8c...        | 5tY7uI0pL3 |
| 004      | File:C:/Users/john_doe/exm.pdf   | N/A               | 7zX4qW6e...        | 2sD8fG1hJ4 |
=====================================================================================================

Extended Metadata Fields:
=====================================================================================================
| Entry ID | Category    | Tags                  | Created Date | Last Modified | Last Used   |
|----------|-------------|-----------------------|--------------|---------------|-------------|
| 001      | Social      | work,professional     | 2024-01-15   | 2024-03-20    | 2024-07-10  |
| 002      | Shopping    | ecommerce,personal    | 2024-02-01   | 2024-02-01    | 2024-07-08  |
| 003      | Financial   | bank,important,secure | 2024-01-10   | 2024-06-15    | 2024-07-11  |
| 004      | Documents   | pdf,local,encrypted   | 2024-03-05   | 2024-03-05    | 2024-07-05  |
=====================================================================================================

Security & Quality Metrics:
=====================================================================================================
| Entry ID | Password Strength| Expiry Date | Reuse Count | Two-Factor Enabled| Notes        |
|----------|------------------|-------------|-------------|-------------------|--------------|
| 001      | Strong (85/100)  | 2024-12-15  | 0           | Yes               | Work account |
| 002      | Medium (65/100)  | 2025-01-01  | 1           | No                | Same as 005  |
| 003      | Excellent(95/100)| 2024-09-10  | 0           | Yes               | Main banking |
| 004      | Weak (40/100)    | Never       | 2           | N/A               | Old PDF pwd  |
=====================================================================================================

Alternative Access Methods (Multiple Keys per Entry):
=====================================================================================================
| Entry ID | Alternative Keys/Aliases                                                   |
|----------|----------------------------------------------------------------------------|
| 001      | "work email", "company login", "example.com", "office account"             |
| 002      | "shopping", "another example", "personal store", "online shopping"         |
| 003      | "bank", "chase", "checking", "main account", "money", "financial"          |
| 004      | "important pdf", "desktop file", "encrypted document", "john_doe file"     |
=====================================================================================================

Technical Implementation Structure (C++ Perspective):
=====================================================================================================
| Field Name        | Data Type              | Purpose                                    |
|-------------------|------------------------|--------------------------------------------|
| entry_id          | std::string            | Unique identifier for each entry           |
| primary_key       | std::string            | Main identifier (URL, path, custom name)   |
| username          | std::string            | Associated username or email               |
| encrypted_password| std::vector<uint8_t>   | Encrypted password data                    |
| salt              | std::vector<uint8_t>   | Unique salt for this entry's encryption    |
| alternative_keys  | std::vector<std::string>| List of aliases for searching             |
| category          | std::string            | User-defined category                      |
| tags              | std::set<std::string>  | Searchable tags                            |
| created_timestamp | std::chrono::time_point| When entry was created                     |
| modified_timestamp| std::chrono::time_point| When entry was last modified               |
| last_used_timestamp| std::chrono::time_point| When password was last accessed           |
| password_strength | int                    | Calculated strength score (0-100)          |
| expiry_date       | std::optional<std::chrono::time_point>| When password expires       |
| reuse_count       | int                    | How many other entries use similar password|
| two_factor_enabled| bool                   | Whether 2FA is enabled for this account    |
| notes             | std::string            | User notes and additional information      |
=====================================================================================================

Hash Map Implementation Strategy:
=====================================================================================================
| Map Type                    | Key                | Value           | Purpose                     |
|-----------------------------|--------------------|-----------------|-----------------------------|
| Primary Map                 | entry_id           | PasswordEntry   | Main storage structure      |
| Search Index                | alternative_key    | entry_id        | Fast lookup by any alias    |
| Category Index              | category           | vector<entry_id>| Group entries by category   |
| Tag Index                   | tag                | vector<entry_id>| Find entries by tag         |
| Expiry Index                | expiry_date        | vector<entry_id>| Track expiring passwords    |
| Reuse Detection Map         | password_hash      | vector<entry_id>| Detect password reuse       |
=====================================================================================================
*/

int main() {
  storePassword();
  return 0;
}
