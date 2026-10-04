#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>

namespace phantom {
// Physical transport effects, separate from reversible inferior memory and
// stop-history retention. Missing intervals are explicit; repeated observations
// never append the same bytes twice. No total order across streams is inferred.
class OutputJournal final {
 public:
  explicit OutputJournal(std::size_t maxBytes = 4 * 1024 * 1024,
                         std::size_t maxSegments = 256);
  void clear();
  // retainedTail represents [totalBytes-retainedTail.size(),totalBytes).
  // Reject inconsistent/regressing observations without modifying saved data.
  bool observe(std::uint64_t totalBytes, std::string_view retainedTail);
  nlohmann::json read(std::uint64_t fromByte, std::size_t byteCount) const;
  std::uint64_t totalBytes() const noexcept { return total_; }
 private:
  struct Segment { std::uint64_t from; std::string bytes; };
  std::deque<Segment> segments_;
  std::size_t maxBytes_, maxSegments_, retainedBytes_ = 0;
  std::uint64_t total_ = 0;
};
} // namespace phantom
