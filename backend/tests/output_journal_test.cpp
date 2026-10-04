#include "phantom/output_journal.hpp"
#include "phantom/validation.hpp"

#include <cassert>
#include <iostream>
#include <limits>

int main() {
  phantom::OutputJournal journal(12,2);
  assert(journal.observe(3,"abc"));
  const auto first = journal.read(0,65536);
  assert(first["segments"][0]["bytesBase64"] == "YWJj");
  assert(journal.observe(3,"abc"));
  assert(first == journal.read(0,65536));
  assert(!journal.observe(3,"axc"));
  assert(!journal.observe(2,"ab"));
  assert(!journal.observe(1,"abc"));
  assert(!journal.observe(phantom::max_json_safe_integer+1,""));
  assert(first == journal.read(0,65536));
  assert(journal.observe(6,"cdef"));
  assert(journal.read(0,6)["segments"][0]["bytesBase64"] == "YWJjZGVm");
  // Unseen bytes between snapshots remain gaps even when earlier bytes survive.
  assert(journal.observe(12,"kl"));
  auto sparse = journal.read(0,12);
  assert(sparse["retainedBytes"] == 8 && sparse["retentionHasGaps"] == true);
  assert(sparse["segments"].size() == 3 && sparse["coverage"] == "partial");
  assert(sparse["segments"][1]["kind"] == "gap");
  assert(sparse["segments"][1]["fromByte"] == 6 && sparse["segments"][1]["throughByte"] == 10);
  assert(journal.read(0,3)["coverage"] == "complete");
  assert(journal.read(2,5)["hasMore"] == true);
  // Segment cap evicts old data independently of byte capacity.
  assert(journal.observe(14,"n"));
  assert(journal.read(0,14)["retainedFromByte"] == 10);
  assert(journal.observe(26,"opqrstuvwxyz"));
  auto evicted = journal.read(0,65536);
  assert(evicted["retainedFromByte"] == 14 && evicted["retainedBytes"] == 12);
  assert(journal.read(14,12)["segments"][0]["bytesBase64"] == "b3BxcnN0dXZ3eHl6");
  assert(journal.read(std::numeric_limits<std::uint64_t>::max(),65536)["segments"].empty());
  assert(journal.read(0,0)["segments"].empty());
  journal.clear();
  assert(journal.totalBytes() == 0 && journal.read(0,12)["segments"].empty());
  const std::string binary("\0\xff\xf0\x9f\x98\x80",6);
  assert(journal.observe(binary.size(),binary));
  assert(journal.read(0,6)["segments"][0]["bytesBase64"] == "AP/wn5iA");
  assert(journal.read(2,2)["segments"][0]["bytesBase64"] == "8J8=");
  phantom::OutputJournal disabled(0,0);
  assert(disabled.observe(3,"abc"));
  assert(disabled.read(0,3)["segments"][0]["kind"] == "gap");
  phantom::OutputJournal tail(4,2);
  assert(tail.observe(6,"abcdef"));
  assert(tail.read(0,6)["retainedFromByte"] == 2);
  assert(tail.observe(8,"gh"));
  assert(tail.read(4,4)["segments"][0]["bytesBase64"] == "ZWZnaA==");
  std::cout << "output journal: exact bytes, overlap, gaps, retention and paging passed\n";
}
