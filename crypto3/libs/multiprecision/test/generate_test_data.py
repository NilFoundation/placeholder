# ---------------------------------------------------------------------------#
# Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
# ---------------------------------------------------------------------------#

import random
import math
import json
import itertools
import sys
from pathlib import Path

OUTPUT_DIR = Path(sys.argv[1])


def generate_instances():
    bits_builtin = [8, 16, 32, 64, 128]
    # bits_other = [1, 12, 17, 256]
    bits_all = [8, 32, 64, 128, 192, 256]

    def shift(l, s):
        return list(map(lambda x: x + s, l))

    bits_all_shifted = [
        bits
        for bits in sorted(
            set(
                bits_all
                + shift(bits_all, -1)
                + shift(bits_all, -2)
                + shift(bits_all, 1)
            )
        )
        if bits >= 1
    ]

    result = []

    def add_instances(bits1, bits2):
        result.append((bits1, "big_uint", bits2, "big_uint"))
        if bits1 in bits_builtin:
            result.append((bits1, "unsigned_builtin", bits2, "big_uint"))
            result.append((bits1, "signed_builtin", bits2, "big_uint"))
        if bits2 in bits_builtin:
            result.append((bits1, "big_uint", bits2, "unsigned_builtin"))
            result.append((bits1, "big_uint", bits2, "signed_builtin"))

    for bits1 in bits_all_shifted:
        if bits1 <= 0:
            continue
        for bits2 in sorted(set(bits_all_shifted + list(range(bits1, bits1 + 3)))):
            if bits2 < bits1:
                continue

            add_instances(bits1, bits2)
            if bits1 != bits2:
                add_instances(bits2, bits1)

    return result


def print_instances(path: Path, types):
    with open(path, "w") as f:
        print(f"// clang-format off", file=f)
        print(file=f)

        prev128 = False
        for type in sorted(types):
            int128 = (type[0] == 128 and type[1][-7:] == "builtin") or (
                type[2] == 128 and type[3][-7:] == "builtin"
            )

            if not int128 and prev128:
                print("#endif", file=f)
                print(file=f)

            if int128 and not prev128:
                print(file=f)
                print("#ifdef NIL_CO3_MP_HAS_INT128", file=f)

            # extra =

            print(
                f"BASE_OPERATIONS_TEST({type[0]:>3}, {type[1]:>16}, {type[2]:>3}, {type[3]:>16})",
                file=f,
            )

            prev128 = int128

        if prev128:
            print("#endif", file=f)

        print(file=f)
        print(f"// clang-format on", file=f)


def generate_big_uint_test_data():
    MAX_BITS_COUNT = 2
    RANDOM_BITS_COUNT = 4
    NEAR_MAX_COUNT = 2

    def random_int(size, rnd):
        return rnd.randint(0 if size == 1 else 2 ** (size - 1), (2**size) - 1)

    def gen_args(bits, type, rnd):
        assert bits >= 1

        signed = type.startswith("signed")
        unsigned_bits = bits - 1 if signed else bits
        max_1 = 2**unsigned_bits

        small_numbers = [0, 1, 2]

        for n in small_numbers:
            if n < max_1:
                yield n
            if signed and n <= max_1:
                yield -n

        if signed:
            yield -max_1

        yield max_1 - 1

        for i in range(MAX_BITS_COUNT):
            yield random_int(unsigned_bits, rnd)

        if signed:
            for i in range(MAX_BITS_COUNT):
                yield -random_int(unsigned_bits, rnd)

        for i in range(RANDOM_BITS_COUNT):
            yield random_int(rnd.randint(1, bits), rnd) - (max_1 if signed else 0)

        for i in range(NEAR_MAX_COUNT):
            yield max_1 - rnd.randint(1, 2 ** (unsigned_bits // 10))

        if signed:
            for i in range(NEAR_MAX_COUNT):
                yield -(max_1 - rnd.randint(0, 2 ** ((bits - 1) // 10)))

    rnd = random.Random(0)

    types = generate_instances()

    print_instances(
        OUTPUT_DIR
        / "include"
        / "generated_test_data"
        / "big_uint_randomized_test_instances.hpp",
        types,
    )

    with open(OUTPUT_DIR / "big_uint_randomized_test_cases.json", "w") as f:
        tests = {}
        for a_bits, a_type, b_bits, b_type in types:
            res_bits = max(
                a_bits if a_type == "big_uint" else 0,
                b_bits if b_type == "big_uint" else 0,
            )
            cases = []
            for a, b in itertools.product(
                sorted(set(gen_args(a_bits, a_type, rnd))),
                sorted(set(gen_args(b_bits, b_type, rnd))),
            ):

                def check_int(i, bits, type):
                    if type.startswith("signed"):
                        return -(2 ** (bits - 1)) <= i < 2 ** (bits - 1)
                    return 0 <= i < 2**bits

                assert check_int(a, a_bits, a_type)
                assert check_int(b, b_bits, b_type)

                mod = 2**res_bits

                cmp_a_b = -1 if a < b else (0 if a == b else 1)

                a_add_b = a + b
                if a_add_b >= mod or a_add_b < 0:
                    a_add_b = None
                a_sub_b = a - b
                if a_sub_b >= mod or a_sub_b < 0:
                    a_sub_b = None
                a_mul_b = a * b
                if a_mul_b >= mod or a < 0 or b < 0:
                    a_mul_b = None

                a_div_b = a // b if a >= 0 and b > 0 else None
                if a_div_b is not None and a_div_b >= mod:
                    a_div_b = None
                a_mod_b = a % b if a >= 0 and b > 0 else None
                assert a_mod_b is None or a_mod_b < mod

                a_wrapping_add_b = ((a + b) % mod + mod) % mod
                a_wrapping_sub_b = ((a - b) % mod + mod) % mod
                a_wrapping_mul_b = ((a * b) % mod + mod) % mod

                a_or_b = a | b
                if a < 0 or b < 0 or a_or_b >= mod:
                    a_or_b = None
                a_and_b = a & b
                if a < 0 or b < 0:
                    a_and_b = None
                a_xor_b = a ^ b
                if a < 0 or b < 0 or a_xor_b >= mod:
                    a_xor_b = None

                cases.append(
                    {
                        "a": hex(a) if a_type == "big_uint" else str(a),
                        "b": hex(b) if b_type == "big_uint" else str(b),
                        "a_add_b": hex(a_add_b) if a_add_b is not None else "",
                        "a_sub_b": hex(a_sub_b) if a_sub_b is not None else "",
                        "a_mul_b": hex(a_mul_b) if a_mul_b is not None else "",
                        "a_div_b": hex(a_div_b) if a_div_b is not None else "",
                        "a_mod_b": hex(a_mod_b) if a_mod_b is not None else "",
                        "a_wrapping_add_b": hex(a_wrapping_add_b),
                        "a_wrapping_sub_b": hex(a_wrapping_sub_b),
                        "a_wrapping_mul_b": hex(a_wrapping_mul_b),
                        "a_or_b": hex(a_or_b) if a_or_b is not None else "",
                        "a_and_b": hex(a_and_b) if a_and_b is not None else "",
                        "a_xor_b": hex(a_xor_b) if a_xor_b is not None else "",
                        "cmp_a_b": cmp_a_b,
                    }
                )
            tests[f"base_operations_{a_bits}_{a_type}_{b_bits}_{b_type}"] = cases
        f.write(json.dumps(tests, indent=4))


def generate_big_mod_test_data():
    ZERO_PROB = 0.05
    MAX_BITS_PROB = 0.1
    EQ_PROB = 0.1
    TEST_CASES = 200

    def gen_arg(bits, m, rnd):
        if rnd.random() < ZERO_PROB:
            return 0
        if rnd.random() < MAX_BITS_PROB:
            return rnd.randint(1 << (bits - 1), m - 1)
        size = rnd.randint(1, bits)
        result = rnd.randint(0 if size == 1 else 1 << (size - 1), (1 << size) - 1)
        assert result < 2**bits
        return result

    rnd = random.Random(0)

    params = [
        ["prime_mod_montgomery_130", 0x314107B9EF725F87FA08F9FDADD4F48BB, 130],
        ["even_mod_130", 0x314107B9EF725F87FA08F9FDADD4F48BA, 130],
        ["goldilocks", 0xFFFFFFFF00000001, 64],
        ["even_mod_17", 0x1E240, 17],
        ["montgomery_17", 0x1E241, 17],
    ]

    with open(
        OUTPUT_DIR / "big_mod_randomized_test_cases.json",
        "w",
    ) as f:
        tests = {}
        for test_name, m, bits in params:
            assert math.ceil(math.log2(m)) == bits
            cases = []
            for i in range(TEST_CASES):
                a = gen_arg(bits, m, rnd)
                if rnd.random() < EQ_PROB:
                    b = a
                else:
                    b = gen_arg(bits, m, rnd)
                cases.append(
                    {
                        "a": hex(a),
                        "b": hex(b),
                        "m": hex(m),
                        "a_m_add_b_m": hex((a + b) % m),
                        "a_m_sub_b_m": hex((a - b + m) % m),
                        "a_m_mul_b_m": hex((a * b) % m),
                        "a_eq_b": a == b,
                        "a_m_pow_b": hex(pow(a, b, m)),
                    }
                )
            tests[test_name] = cases
        f.write(json.dumps(tests, indent=4))


if __name__ == "__main__":
    generate_big_uint_test_data()
    generate_big_mod_test_data()
