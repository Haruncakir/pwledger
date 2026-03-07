#include <pwledger/VaultSerializer.h>

#include <pwledger/SecretEntry.h>

namespace pwledger {

std::vector<std::uint8_t> VaultSerializer::serialize(const PrimaryTable& table) {
  std::vector<std::uint8_t> out;
  // Rough preallocation estimate: 128 bytes per entry + header
  out.reserve(13 + table.size() * 128);

  // Header
  write_bytes(out, kMagic, 4);
  write_u8(out, kVersion);
  write_u64(out, static_cast<std::uint64_t>(table.size()));

  // Entries
  for (const auto& [uuid, entry] : table) {
    write_bytes(out, uuid.bytes.data(), 16);

    write_string(out, entry.primary_key);
    write_string(out, entry.username_or_email);

    // Secret data reading requires access guard
    entry.plaintext_secret.with_read_access([&](std::span<const char> buf) {
      std::size_t len = ::strnlen(buf.data(), buf.size());
      write_u32(out, static_cast<std::uint32_t>(len));
      write_bytes(out, reinterpret_cast<const std::uint8_t*>(buf.data()), len);
    });

    entry.salt.with_read_access([&](std::span<const char> buf) {
      write_u32(out, static_cast<std::uint32_t>(buf.size()));
      write_bytes(out, reinterpret_cast<const std::uint8_t*>(buf.data()), buf.size());
    });

    // Metadata
    write_time(out, entry.metadata.created_at);
    write_time(out, entry.metadata.last_modified_at);
    write_time(out, entry.metadata.last_used_at);

    // Security Policy
    write_u32(out, static_cast<std::uint32_t>(entry.security_policy.strength_score));
    write_u32(out, static_cast<std::uint32_t>(entry.security_policy.reuse_count));
    write_u8(out, entry.security_policy.two_fa_enabled ? 1 : 0);

    if (entry.security_policy.expires_at.has_value()) {
      write_u8(out, 1);
      write_time(out, *entry.security_policy.expires_at);
    } else {
      write_u8(out, 0);
    }

    write_string(out, entry.security_policy.note);
  }

  return out;
}

PrimaryTable VaultSerializer::deserialize(const std::uint8_t* data, std::size_t size) {
  PrimaryTable table;
  std::size_t pos = 0;

  auto require = [&](std::size_t bytes) {
    if (pos + bytes > size) {
      throw std::runtime_error("Vault payload truncated");
    }
  };

  require(4);
  if (std::memcmp(data + pos, kMagic, 4) != 0) {
    throw std::runtime_error("Invalid vault magic number");
  }
  pos += 4;

  require(1);
  if (data[pos] != kVersion) {
    throw std::runtime_error("Unsupported vault version");
  }
  pos += 1;

  std::uint64_t num_entries = read_u64(data, pos, size);

  for (std::uint64_t i = 0; i < num_entries; ++i) {
    require(16);
    Uuid uuid;
    std::memcpy(uuid.bytes.data(), data + pos, 16);
    pos += 16;

    std::string pk = read_string(data, pos, size);
    std::string uoe = read_string(data, pos, size);

    std::uint32_t secret_len = read_u32(data, pos, size);
    require(secret_len);
    const std::uint8_t* secret_data = data + pos;
    pos += secret_len;

    std::uint32_t salt_len = read_u32(data, pos, size);
    require(salt_len);
    const std::uint8_t* salt_data = data + pos;
    pos += salt_len;

    // SecretEntry needs the max allocation sizes (kMaxSecretBytes, kSaltBytes)
    // We derive them here or pad up to match the runtime defaults (256, 16).
    // If the serialized secret is longer than 256, we allocate exactly its size.
    std::size_t alloc_secret = (secret_len > 256) ? secret_len : 256;
    std::size_t alloc_salt = (salt_len > 16) ? salt_len : 16;

    SecretEntry entry(std::move(pk), std::move(uoe), alloc_secret, alloc_salt);

    // Copy bytes into the hardened buffer
    entry.plaintext_secret.with_write_access([&](std::span<char> buf) {
      std::memset(buf.data(), 0, buf.size());
      std::memcpy(buf.data(), secret_data, secret_len);
    });

    entry.salt.with_write_access([&](std::span<char> buf) {
      std::memset(buf.data(), 0, buf.size());
      std::memcpy(buf.data(), salt_data, salt_len);
    });

    entry.metadata.created_at = read_time(data, pos, size);
    entry.metadata.last_modified_at = read_time(data, pos, size);
    entry.metadata.last_used_at = read_time(data, pos, size);

    entry.security_policy.strength_score = static_cast<int>(read_u32(data, pos, size));
    entry.security_policy.reuse_count = static_cast<int>(read_u32(data, pos, size));
    
    require(1);
    entry.security_policy.two_fa_enabled = (data[pos++] != 0);

    require(1);
    if (data[pos++] != 0) {
      entry.security_policy.expires_at = read_time(data, pos, size);
    }

    entry.security_policy.note = read_string(data, pos, size);

    table.emplace(uuid, std::move(entry));
  }

  return table;
}

void VaultSerializer::write_u8(std::vector<std::uint8_t>& out, std::uint8_t val) {
  out.push_back(val);
}

void VaultSerializer::write_u32(std::vector<std::uint8_t>& out, std::uint32_t val) {
  out.push_back(static_cast<std::uint8_t>(val & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
}

void VaultSerializer::write_u64(std::vector<std::uint8_t>& out, std::uint64_t val) {
  out.push_back(static_cast<std::uint8_t>(val & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 24) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 32) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 40) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 48) & 0xFF));
  out.push_back(static_cast<std::uint8_t>((val >> 56) & 0xFF));
}

void VaultSerializer::write_bytes(std::vector<std::uint8_t>& out, const std::uint8_t* data, std::size_t len) {
  out.insert(out.end(), data, data + len);
}

void VaultSerializer::write_string(std::vector<std::uint8_t>& out, const std::string& str) {
  std::uint32_t len = static_cast<std::uint32_t>(str.size());
  write_u32(out, len);
  write_bytes(out, reinterpret_cast<const std::uint8_t*>(str.data()), len);
}

void VaultSerializer::write_time(std::vector<std::uint8_t>& out, std::chrono::system_clock::time_point tp) {
  auto sec = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
  write_u64(out, static_cast<std::uint64_t>(sec));
}

std::uint32_t VaultSerializer::read_u32(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
  if (pos + 4 > size) throw std::runtime_error("Truncated buffer");
  std::uint32_t val = static_cast<std::uint32_t>(data[pos]) |
                      (static_cast<std::uint32_t>(data[pos + 1]) << 8) |
                      (static_cast<std::uint32_t>(data[pos + 2]) << 16) |
                      (static_cast<std::uint32_t>(data[pos + 3]) << 24);
  pos += 4;
  return val;
}

std::uint64_t VaultSerializer::read_u64(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
  if (pos + 8 > size) throw std::runtime_error("Truncated buffer");
  std::uint64_t val = static_cast<std::uint64_t>(data[pos]) |
                      (static_cast<std::uint64_t>(data[pos + 1]) << 8) |
                      (static_cast<std::uint64_t>(data[pos + 2]) << 16) |
                      (static_cast<std::uint64_t>(data[pos + 3]) << 24) |
                      (static_cast<std::uint64_t>(data[pos + 4]) << 32) |
                      (static_cast<std::uint64_t>(data[pos + 5]) << 40) |
                      (static_cast<std::uint64_t>(data[pos + 6]) << 48) |
                      (static_cast<std::uint64_t>(data[pos + 7]) << 56);
  pos += 8;
  return val;
}

std::string VaultSerializer::read_string(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
  std::uint32_t len = read_u32(data, pos, size);
  if (pos + len > size) throw std::runtime_error("Truncated string");
  std::string str(reinterpret_cast<const char*>(data + pos), len);
  pos += len;
  return str;
}

std::chrono::system_clock::time_point VaultSerializer::read_time(const std::uint8_t* data, std::size_t& pos, std::size_t size) {
  std::int64_t sec = static_cast<std::int64_t>(read_u64(data, pos, size));
  return std::chrono::system_clock::time_point(std::chrono::seconds(sec));
}

}  // namespace pwledger
