#include <pwledger/uuid.h>

namespace pwledger {

// Generates a version-4 (random) UUID per RFC 4122.
// NOT cryptographically secure — see DESIGN NOTES.
Uuid Uuid::generate() {
  Uuid id;

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<std::uint64_t> dist;

  std::uint64_t part1 = dist(gen);
  std::uint64_t part2 = dist(gen);

  std::memcpy(id.bytes.data(), &part1, 8);
  std::memcpy(id.bytes.data() + 8, &part2, 8);

  // Set version to 4 (bits 4–7 of byte 6).
  id.bytes[6] = (id.bytes[6] & 0x0F) | 0x40;

  // Set variant to RFC 4122 (bits 6–7 of byte 8).
  id.bytes[8] = (id.bytes[8] & 0x3F) | 0x80;
  return id;
}

// Formats as the canonical RFC 4122 representation:
//   xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
std::string Uuid::to_string() const {
  // Byte groups: 4-2-2-2-6, separated by hyphens.
  constexpr int kGroups[] = {4, 2, 2, 2, 6};
  constexpr int kNumGroups = 5;

  std::ostringstream oss;
  oss << std::hex << std::setfill('0');

  int byte_index = 0;
  for (int g = 0; g < kNumGroups; ++g) {
    if (g > 0) {
      oss << '-';
    }
    for (int i = 0; i < kGroups[g]; ++i) {
      oss << std::setw(2) << static_cast<unsigned int>(bytes[byte_index++]);
    }
  }
  return oss.str();
}

// Parses a UUID from its string representation. Accepts both the canonical
// 36-character form (with hyphens) and the 32-character compact form.
// Returns std::nullopt on malformed input rather than throwing, so callers
// can provide user-friendly error messages.
std::optional<Uuid> Uuid::from_string(std::string_view str) {
  // Strip hyphens to get a uniform 32-character hex string.
  std::string hex;
  hex.reserve(32);
  for (char c : str) {
    if (c == '-') {
      continue;
    }
    if (!is_hex_digit(c)) {
      return std::nullopt;
    }
    hex += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  if (hex.size() != 32) {
    return std::nullopt;
  }

  Uuid id;
  for (std::size_t i = 0; i < 16; ++i) {
    id.bytes[i] = static_cast<std::uint8_t>((hex_value(hex[i * 2]) << 4) | hex_value(hex[i * 2 + 1]));
  }
  return id;
}

std::ostream& operator<<(std::ostream& os, const Uuid& uuid) {
  return os << uuid.to_string();
}

bool Uuid::is_hex_digit(char c) noexcept {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int Uuid::hex_value(char c) noexcept {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return 0;  // unreachable after is_hex_digit check
}

}  // namespace pwledger
