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

#ifndef PWLEDGER_ENTRYMETADATA_H
#define PWLEDGER_ENTRYMETADATA_H

#include <chrono>

namespace pwledger {

// ----------------------------------------------------------------------------
// EntryMetadata
// ----------------------------------------------------------------------------
// Lifecycle timestamps for a stored credential. All fields use system_clock
// so that timestamps are comparable and serializable to wall-clock time.
struct EntryMetadata {
  std::chrono::system_clock::time_point created_at;
  std::chrono::system_clock::time_point last_modified_at;
  std::chrono::system_clock::time_point last_used_at;
};

}  // namespace pwledger

#endif  // PWLEDGER_ENTRYMETADATA_H
