#include "segment.h"

#include <optional>

void UpdateSegments(std::set<Segment>& segments, const Segment& new_segment) {
  std::optional<std::set<Segment>::iterator> start_remover = std::nullopt;

  auto [segment_start, segment_end, version] = new_segment;
  auto start_overlap = segments.lower_bound({segment_start, 0, 0});
  if (start_overlap != segments.begin()) {
    auto to_edit = std::prev(start_overlap);
    const auto [prev_start, prev_end, prev_version] = *to_edit;
    if (prev_end > segment_start) {
      segments.emplace(prev_start, segment_start, prev_version);
      start_remover = to_edit;
    }
  }

  auto end_overlap = segments.lower_bound({segment_end, 0, 0});
  if (end_overlap != segments.begin()) {
    auto to_edit = std::prev(end_overlap);
    const auto [prev_start, prev_end, prev_version] = *to_edit;
    if (prev_end > segment_end) {
      segments.emplace(segment_end, prev_end, prev_version);
    }
  }

  if (start_remover.has_value()) {
    segments.erase(start_remover.value());
  }
  segments.erase(start_overlap, end_overlap);
  segments.emplace(segment_start, segment_end, version);
}
