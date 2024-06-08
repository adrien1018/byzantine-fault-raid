#pragma once

#include <cstdint>
#include <set>
#include <tuple>

using Segment =
    std::tuple<uint64_t, uint64_t, uint32_t>;  // (start, end, version)

void UpdateSegments(std::set<Segment>& segments, const Segment& new_segment);
