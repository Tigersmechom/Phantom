#include "phantom/output_journal.hpp"
#include "phantom/validation.hpp"

#include <algorithm>

namespace phantom {
namespace {
std::string base64(std::string_view bytes) {
  constexpr char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out; out.reserve((bytes.size()+2)/3*4);
  for (std::size_t i=0; i<bytes.size(); i+=3) {
    const auto a = static_cast<unsigned char>(bytes[i]);
    const auto b = i+1 < bytes.size() ? static_cast<unsigned char>(bytes[i+1]) : 0;
    const auto c = i+2 < bytes.size() ? static_cast<unsigned char>(bytes[i+2]) : 0;
    out += digits[a >> 2]; out += digits[((a & 3) << 4) | (b >> 4)];
    out += i+1 < bytes.size() ? digits[((b & 15) << 2) | (c >> 6)] : '=';
    out += i+2 < bytes.size() ? digits[c & 63] : '=';
  }
  return out;
}
}
OutputJournal::OutputJournal(std::size_t maxBytes, std::size_t maxSegments)
    : maxBytes_(std::min(maxBytes, std::size_t{16 * 1024 * 1024})),
      maxSegments_(std::min(maxSegments, std::size_t{1024})) {}

void OutputJournal::clear() { segments_.clear(); retainedBytes_ = 0; total_ = 0; }

bool OutputJournal::observe(std::uint64_t totalBytes, std::string_view tail) {
  if (totalBytes > max_json_safe_integer || totalBytes < total_ || tail.size() > totalBytes) return false;
  const auto from = totalBytes - tail.size();
  // The transport counter identifies bytes, not merely a string length. A
  // mismatched overlap must not quietly replace a previous physical effect.
  for (const auto& segment : segments_) {
    const auto begin = std::max(from, segment.from);
    const auto end = std::min(totalBytes, segment.from + segment.bytes.size());
    if (begin < end && tail.substr(begin-from, end-begin) !=
                      std::string_view(segment.bytes).substr(begin-segment.from, end-begin)) return false;
  }
  const auto begin = std::max(from,total_);
  if (begin < totalBytes && maxBytes_ && maxSegments_) {
    // Avoid allocating an oversized temporary merely to trim it immediately.
    const auto keptBegin = std::max(begin,totalBytes-std::min<std::uint64_t>(maxBytes_,totalBytes));
    auto bytes = std::string(tail.substr(keptBegin-from));
    if (!segments_.empty() && segments_.back().from+segments_.back().bytes.size() == keptBegin)
      segments_.back().bytes += bytes;
    else segments_.push_back({keptBegin,std::move(bytes)});
    retainedBytes_ += totalBytes-keptBegin;
    while (!segments_.empty() && (retainedBytes_ > maxBytes_ || segments_.size() > maxSegments_)) {
      auto& front = segments_.front();
      const auto excess = retainedBytes_ > maxBytes_ ? retainedBytes_-maxBytes_ : std::size_t{0};
      const auto drop = segments_.size() > maxSegments_ ? front.bytes.size() : std::min(excess,front.bytes.size());
      retainedBytes_ -= drop;
      if (drop == front.bytes.size()) segments_.pop_front();
      else { front.from += drop; front.bytes.erase(0,drop); }
    }
  }
  total_ = totalBytes;
  return true;
}

nlohmann::json OutputJournal::read(std::uint64_t fromByte, std::size_t byteCount) const {
  const auto begin = std::min(fromByte,total_);
  const auto end = begin + std::min<std::uint64_t>(std::min<std::size_t>(byteCount,65536),total_-begin);
  auto pieces = nlohmann::json::array();
  auto cursor = begin;
  bool complete = true;
  const auto gap = [&](std::uint64_t a, std::uint64_t b) {
    complete = false;
    pieces.push_back({{"kind","gap"},{"fromByte",a},{"throughByte",b},{"reason","not-retained"}});
  };
  for (const auto& segment : segments_) {
    const auto a = std::max(begin,segment.from), b = std::min(end,segment.from+segment.bytes.size());
    if (a >= b) continue;
    if (a > cursor) gap(cursor,a);
    pieces.push_back({{"kind","bytes"},{"fromByte",a},{"throughByte",b},
                      {"bytesBase64",base64(std::string_view(segment.bytes).substr(a-segment.from,b-a))}});
    cursor = b;
  }
  if (cursor < end) gap(cursor,end);
  return {{"fromByte",begin},{"throughByte",end},{"totalBytes",total_},
          {"retainedFromByte",segments_.empty() ? total_ : segments_.front().from},
          {"retainedBytes",retainedBytes_},{"retentionHasGaps",retainedBytes_ < total_},
          {"coverage",complete ? "complete" : "partial"},{"hasMore",end < total_},{"segments",pieces}};
}
} // namespace phantom
