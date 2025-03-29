#pragma once

#include <cstdint>

constexpr std::uint64_t DriverHashString(const char* input)
{
    constexpr std::uint64_t fnv_prime = 1099511628211ULL;
    constexpr std::uint64_t offset_basis = 14695981039346656037ULL;

    std::uint64_t hash = offset_basis;
    std::uint64_t c = 0;

    while (c = static_cast<std::uint64_t>(*input++))
    {
        hash ^= c;
        hash *= fnv_prime;
    }

    return hash;
}

#define DRIVER_HASH_STRING(x) [](){ constexpr uint64_t StringHash = DriverHashString(x); return StringHash; }()