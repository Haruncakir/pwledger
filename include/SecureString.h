/* Copyright (c) 2025 Harun
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

#ifndef PWLEDGER_SECURESTRING_H
#define PWLEDGER_SECURESTRING_H

#include <string>

namespace pwledger {

// to enforce usage of safe alternatives of malloc, memzero ...
// CRTP
template <class CustomSecureAllocator>
struct SecureAllocator {};  // maybe SecureCharTAllocator
                            // if not gonna be used elsewhere but SecureString

// std::string doesn't actually erase its memory when it goes
// out of scope or gets reassigned. Instead, it simply marks that
// memory as available for reuse. So the information is still
// there, so assume that you store password or something sensitive
// in std::string, the memory can be paged out, can be find in
// swap memory or worse in the disk which is non-volatile storage
// so the sensitive information will hang around for a while
// custom allocator to std::string doesn't solve the security problems
// due to std::string can make hidden copies in some operations
// the C++ standard allows implementations to use something called
// the Small String Optimization (SSO). This means that short strings
// might be stored directly inside the string object itself,
// not in allocated memory at all. Even the custom allocator never even
//  sees this data, so it can't zero it when the string is destroyed.
template <typename CharT, class Traits = std::char_traits<CharT>, class Allocator = std::allocator<CharT>>
class BasicSecureString {
public:
  // copying to/from is not allowed
  BasicSecureString(const BasicSecureString&) = delete;
  BasicSecureString& operator=(const BasicSecureString&) = delete;

  // according to rule of 5 we need explicit definitions
  // see: https://en.cppreference.com/w/cpp/language/rule_of_three.html
  ~BasicSecureString() = default;
  BasicSecureString(const BasicSecureString&&) = default;
  BasicSecureString& operator=(BasicSecureString&&) = default;
};

// using secure_string = BasicSecureString<char>;

// for simplicity we'll use std::string for now
using secure_string = std::string;

}  // namespace pwledger

#endif  // PWLEDGER_SECURESTRING_H
