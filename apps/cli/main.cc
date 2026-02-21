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

#include <pwledger/Secret.h>
#include <pwledger/TerminalManager.h>
#include <unordered_map>

struct SecretEntry {
    std::string primary_key;
    std::string username_or_email;
    pwledger::Secret encrypted_secret;
    pwledger::Secret salt;

    ~SecretEntry() { encrypted_secret.~Secret(); salt.~Secret(); }
};

struct ExtendedMetaData {
    std::chrono::time_point created_data;
    std::chrono::time_point last_modified;
    std::chrono::time_point last_used;
};

struct SecurityQualityAddOns {
    int secret_strength;
    std::optional<std::chrono::time_point> expiry_data;
    int reuse_count;
    bool two_fa;
    std::string note;
};

std::unordered_map<uuid, SecretEntry> primary_table;

int main() {
  return 0;
}
