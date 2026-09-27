#include "phantom/sha256.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace phantom {
namespace {
constexpr std::array<std::uint32_t, 64> k = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};
constexpr std::array<std::uint32_t, 8> initial = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};
constexpr std::uint32_t rotr(std::uint32_t x, unsigned n) { return std::rotr(x, n); }
void block(std::uint32_t* h, const std::byte* data) {
  std::array<std::uint32_t, 64> w{};
  for (unsigned i = 0; i < 16; ++i) {
    const auto p = reinterpret_cast<const unsigned char*>(data + i * 4);
    w[i] = (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
  }
  for (unsigned i = 16; i < 64; ++i) {
    const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], q=h[7];
  for (unsigned i = 0; i < 64; ++i) {
    const auto S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const auto ch = (e & f) ^ (~e & g);
    const auto t1 = q + S1 + ch + k[i] + w[i];
    const auto S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const auto maj = (a & b) ^ (a & c) ^ (b & c);
    const auto t2 = S0 + maj;
    q=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=q;
}
} // namespace

std::string sha256_hex(std::span<const std::byte> bytes) {
  std::uint32_t h[8]; for (unsigned i=0;i<8;++i) h[i]=initial[i];
  const auto full = bytes.size() / 64;
  for (std::size_t i=0; i<full; ++i) block(h, bytes.data()+i*64);
  std::array<std::byte, 128> tail{};
  const auto rest = bytes.size() - full*64;
  for (std::size_t i=0;i<rest;++i) tail[i]=bytes[full*64+i];
  tail[rest] = std::byte{0x80};
  const std::uint64_t bits = static_cast<std::uint64_t>(bytes.size()) * 8;
  const auto offset = (rest + 1 <= 55) ? 56u : 120u;
  for (unsigned i=0;i<8;++i) tail[offset+7-i] = static_cast<std::byte>((bits>>(i*8))&0xff);
  block(h, tail.data()); if (offset==120) block(h, tail.data()+64);
  std::ostringstream out; out << std::hex << std::setfill('0');
  for (const auto x : h) out << std::setw(8) << x;
  return out.str();
}
}
