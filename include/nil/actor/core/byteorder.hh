//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#pragma once

#include <algorithm>
#ifdef __linux
#include <endian.h>
#elif defined(__APPLE__)
#include <machine/endian.h>
#endif
#include <nil/actor/core/unaligned.hh>

namespace nil {
    namespace actor {

        inline uint8_t cpu_to_le(uint8_t x) noexcept {
            return x;
        }
        inline uint8_t le_to_cpu(uint8_t x) noexcept {
            return x;
        }
        inline uint16_t cpu_to_le(uint16_t x) noexcept {
            return htole16(x);
        }
        inline uint16_t le_to_cpu(uint16_t x) noexcept {
            return le16toh(x);
        }
        inline uint32_t cpu_to_le(uint32_t x) noexcept {
            return htole32(x);
        }
        inline uint32_t le_to_cpu(uint32_t x) noexcept {
            return le32toh(x);
        }
        inline uint64_t cpu_to_le(uint64_t x) noexcept {
            return htole64(x);
        }
        inline uint64_t le_to_cpu(uint64_t x) noexcept {
            return le64toh(x);
        }

        inline int8_t cpu_to_le(int8_t x) noexcept {
            return x;
        }
        inline int8_t le_to_cpu(int8_t x) noexcept {
            return x;
        }
        inline int16_t cpu_to_le(int16_t x) noexcept {
            return htole16(x);
        }
        inline int16_t le_to_cpu(int16_t x) noexcept {
            return le16toh(x);
        }
        inline int32_t cpu_to_le(int32_t x) noexcept {
            return htole32(x);
        }
        inline int32_t le_to_cpu(int32_t x) noexcept {
            return le32toh(x);
        }
        inline int64_t cpu_to_le(int64_t x) noexcept {
            return htole64(x);
        }
        inline int64_t le_to_cpu(int64_t x) noexcept {
            return le64toh(x);
        }

        inline uint8_t cpu_to_be(uint8_t x) noexcept {
            return x;
        }
        inline uint8_t be_to_cpu(uint8_t x) noexcept {
            return x;
        }
        inline uint16_t cpu_to_be(uint16_t x) noexcept {
            return htobe16(x);
        }
        inline uint16_t be_to_cpu(uint16_t x) noexcept {
            return be16toh(x);
        }
        inline uint32_t cpu_to_be(uint32_t x) noexcept {
            return htobe32(x);
        }
        inline uint32_t be_to_cpu(uint32_t x) noexcept {
            return be32toh(x);
        }
        inline uint64_t cpu_to_be(uint64_t x) noexcept {
            return htobe64(x);
        }
        inline uint64_t be_to_cpu(uint64_t x) noexcept {
            return be64toh(x);
        }

        inline int8_t cpu_to_be(int8_t x) noexcept {
            return x;
        }
        inline int8_t be_to_cpu(int8_t x) noexcept {
            return x;
        }
        inline int16_t cpu_to_be(int16_t x) noexcept {
            return htobe16(x);
        }
        inline int16_t be_to_cpu(int16_t x) noexcept {
            return be16toh(x);
        }
        inline int32_t cpu_to_be(int32_t x) noexcept {
            return htobe32(x);
        }
        inline int32_t be_to_cpu(int32_t x) noexcept {
            return be32toh(x);
        }
        inline int64_t cpu_to_be(int64_t x) noexcept {
            return htobe64(x);
        }
        inline int64_t be_to_cpu(int64_t x) noexcept {
            return be64toh(x);
        }

        template<typename T>
        inline T cpu_to_le(const unaligned<T> &v) noexcept {
            return cpu_to_le(T(v));
        }

        template<typename T>
        inline T le_to_cpu(const unaligned<T> &v) noexcept {
            return le_to_cpu(T(v));
        }

        template<typename T>
        inline T read_le(const char *p) noexcept {
            T datum;
            std::copy_n(p, sizeof(T), reinterpret_cast<char *>(&datum));
            return le_to_cpu(datum);
        }

        template<typename T>
        inline void write_le(char *p, T datum) noexcept {
            datum = cpu_to_le(datum);
            std::copy_n(reinterpret_cast<const char *>(&datum), sizeof(T), p);
        }

        template<typename T>
        inline T read_be(const char *p) noexcept {
            T datum;
            std::copy_n(p, sizeof(T), reinterpret_cast<char *>(&datum));
            return be_to_cpu(datum);
        }

        template<typename T>
        inline void write_be(char *p, T datum) noexcept {
            datum = cpu_to_be(datum);
            std::copy_n(reinterpret_cast<const char *>(&datum), sizeof(T), p);
        }

        template<typename T>
        inline T consume_be(const char *&p) noexcept {
            auto ret = read_be<T>(p);
            p += sizeof(T);
            return ret;
        }

        template<typename T>
        inline void produce_be(char *&p, T datum) noexcept {
            write_be<T>(p, datum);
            p += sizeof(T);
        }

    }    // namespace actor
}    // namespace nil
