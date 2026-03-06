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

#ifndef PWLEDGER_ENTRYSECURITYPOLICY_H
#define PWLEDGER_ENTRYSECURITYPOLICY_H

#include <chrono>
#include <optional>
#include <string>

namespace pwledger {

// ----------------------------------------------------------------------------
// EntrySecurityPolicy
// ----------------------------------------------------------------------------
// Security attributes and policy constraints for a stored credential.
//
// strength_score:  Estimated bit-strength of the plaintext secret (e.g.,
//                  from zxcvbn or a similar estimator). 0 means not yet
//                  evaluated. Consider a newtype wrapper if invariants
//                  (non-negative, bounded range) need enforcement.
// reuse_count:     Number of other entries sharing an identical secret.
//                  Populated by a background audit pass; used to surface
//                  reuse warnings in the UI.
// two_fa_enabled:  Whether a second factor is associated with this entry.
// expires_at:      Optional expiry deadline. nullopt means no expiry policy.
// note:            Free-form user annotation. Stored in plaintext; treat as
//                  non-sensitive. If notes may contain sensitive content,
//                  migrate this field to a Secret.
struct EntrySecurityPolicy {
  int strength_score = 0;
  int reuse_count = 0;
  bool two_fa_enabled = false;
  std::optional<std::chrono::system_clock::time_point> expires_at;
  std::string note;
};

}  // namespace pwledger

#endif  // PWLEDGER_ENTRYSECURITYPOLICY_H
