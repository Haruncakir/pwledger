#include <pwledger/SecretEntry.h>

namespace pwledger {

SecretEntry::SecretEntry(std::string pk, std::string user, std::size_t secret_size, std::size_t salt_size)
    : primary_key(std::move(pk))
    , username_or_email(std::move(user))
    , plaintext_secret(secret_size)
    , salt(salt_size)
    , metadata{std::chrono::system_clock::now(), std::chrono::system_clock::now(), std::chrono::system_clock::now()} {
}

}  // namespace pwledger
