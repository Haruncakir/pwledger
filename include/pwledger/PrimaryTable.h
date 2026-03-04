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

#ifndef PWLEDGER_PRIMARYTABLE_H
#define PWLEDGER_PRIMARYTABLE_H

#include <pwledger/SecretEntry.h>
#include <pwledger/uuid.h>

#include <unordered_map>

namespace pwledger {

// ----------------------------------------------------------------------------
// PrimaryTable
// ----------------------------------------------------------------------------
// The top-level credential store: a map from UUID to SecretEntry.
// unordered_map provides O(1) average lookup by UUID. If ordered iteration
// or range queries are needed, std::map<Uuid, SecretEntry> is the alternative.
//
// SecretEntry is move-only; insertions use std::move or emplace.
using PrimaryTable = std::unordered_map<Uuid, SecretEntry>;

}  // namespace pwledger

#endif  // PWLEDGER_PRIMARYTABLE_H
