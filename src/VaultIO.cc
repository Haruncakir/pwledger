#include <pwledger/VaultIO.h>

#include <sodium.h>

namespace pwledger {

bool VaultIO::vault_exists(const std::filesystem::path& path) {
  return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
}

void VaultIO::save_vault(const std::filesystem::path& path, const PrimaryTable& table, std::string_view password) {
  // 1. Serialize to plaintext bytes
  std::vector<std::uint8_t> plaintext = VaultSerializer::serialize(table);

  // 2. Encrypt
  std::vector<std::uint8_t> ciphertext = VaultCrypto::encrypt_vault(password, plaintext);

  // 3. Clear plaintext from memory immediately (best effort; std::vector
  // doesn't guarantee zeroing, but we can do it manually before destruction)
  sodium_memzero(plaintext.data(), plaintext.size());
  // Also clear its capacity if it reallocated
  plaintext.clear();
  plaintext.shrink_to_fit();

  // 4. Atomic write
  std::filesystem::path temp_path = path;
  temp_path += ".tmp";

  {
    std::ofstream ofs(temp_path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
      throw std::runtime_error("Failed to open temporary vault file for writing");
    }
    ofs.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<std::streamsize>(ciphertext.size()));
    if (!ofs.good()) {
      throw std::runtime_error("Write to temporary vault file failed");
    }
  }

  // Set restrictive permissions on the temp file before renaming
  std::filesystem::permissions(
      temp_path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
      std::filesystem::perm_options::replace);

  std::filesystem::rename(temp_path, path);
}

PrimaryTable VaultIO::load_vault(const std::filesystem::path& path, std::string_view password) {
  if (!vault_exists(path)) {
    throw std::runtime_error("Vault file does not exist");
  }

  // 1. Read entire file
  std::vector<std::uint8_t> ciphertext;
  {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
      throw std::runtime_error("Failed to open vault file for reading");
    }
    auto size = ifs.tellg();
    if (size < 0) {
      throw std::runtime_error("Failed to determine vault file size");
    }
    ifs.seekg(0, std::ios::beg);
    ciphertext.resize(static_cast<std::size_t>(size));
    if (!ifs.read(reinterpret_cast<char*>(ciphertext.data()), size)) {
      throw std::runtime_error("Failed to read vault file");
    }
  }

  // 2. Decrypt
  std::vector<std::uint8_t> plaintext = VaultCrypto::decrypt_vault(password, ciphertext);

  // 3. Deserialize
  PrimaryTable table;
  try {
    table = VaultSerializer::deserialize(plaintext.data(), plaintext.size());
  } catch (...) {
    sodium_memzero(plaintext.data(), plaintext.size());
    throw;
  }

  // 4. Clear plaintext
  sodium_memzero(plaintext.data(), plaintext.size());
  
  return table;
}

}  // namespace pwledger
