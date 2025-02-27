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
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent


def generate_big_uint_test_data():
    ZERO_PROB = 0.05
    MAX_BITS_PROB = 0.1
    NEAR_MAX_PROB = 0.1
    EQ_PROB = 0.1
    TEST_CASES = 1000

    def gen_arg(bits, rnd):
        if rnd.random() < ZERO_PROB:
            return 0
        if rnd.random() < NEAR_MAX_PROB:
            return 2**bits - rnd.randint(1, 2 ** (bits // 10))
        if rnd.random() < MAX_BITS_PROB:
            size = bits
        else:
            size = rnd.randint(1, bits)
        result = rnd.randint(0 if size == 1 else 2 **
                             (size - 1), (2**size) - 1)
        assert result < 2**bits
        return result

    rnd = random.Random(0)

    bits = [[12, 17], [260, 130], [128, 256], [128, 128]]

    with open(SOURCE_DIR / "big_uint_randomized.json", "w") as f:
        tests = {}
        for a_bits, b_bits in bits:
            max_bits = max(a_bits, b_bits)
            cases = []
            for i in range(TEST_CASES):
                a = gen_arg(a_bits, rnd)

                if a < 2 ** b_bits and rnd.random() < EQ_PROB:
                    b = a
                else:
                    b = gen_arg(b_bits, rnd)

                mod = 2**max_bits

                cmp_a_b = -1 if a < b else (0 if a == b else 1)

                a_add_b = a + b
                if a_add_b >= mod:
                    a_add_b = None
                a_sub_b = a - b
                if a_sub_b < 0:
                    a_sub_b = None
                a_mul_b = a * b
                if a_mul_b >= mod:
                    a_mul_b = None

                a_div_b = a // b if b != 0 else None
                a_mod_b = a % b if b != 0 else None

                a_wrapping_add_b = (a + b) % mod
                a_wrapping_sub_b = (a - b + mod) % mod
                a_wrapping_mul_b = (a * b) % mod

                a_or_b = a | b
                a_and_b = a & b
                a_xor_b = a ^ b

                cases.append(
                    {
                        "a": hex(a),
                        "b": hex(b),
                        "a_add_b": hex(a_add_b) if a_add_b is not None else "",
                        "a_sub_b": hex(a_sub_b) if a_sub_b is not None else "",
                        "a_mul_b": hex(a_mul_b) if a_mul_b is not None else "",
                        "a_div_b": hex(a_div_b) if a_div_b is not None else "",
                        "a_mod_b": hex(a_mod_b) if a_mod_b is not None else "",
                        "a_wrapping_add_b": hex(a_wrapping_add_b),
                        "a_wrapping_sub_b": hex(a_wrapping_sub_b),
                        "a_wrapping_mul_b": hex(a_wrapping_mul_b),
                        "a_or_b": hex(a_or_b),
                        "a_and_b": hex(a_and_b),
                        "a_xor_b": hex(a_xor_b),
                        "cmp_a_b": cmp_a_b,
                    }
                )
            tests[f"base_operations_{a_bits}_{b_bits}"] = cases
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
        result = rnd.randint(0 if size == 1 else 1 <<
                             (size - 1), (1 << size) - 1)
        assert result < 2**bits
        return result

    params = [
        ["prime_mod_montgomery_130", 0x314107B9EF725F87FA08F9FDADD4F48BB, 130],
        ["even_mod_130", 0x314107B9EF725F87FA08F9FDADD4F48BA, 130],
        ["goldilocks", 0xFFFFFFFF00000001, 64],
        ["mersenne31", 0x7FFFFFFF, 31],
        ["koalabear", 0x7F000001, 31],
        ["babybear", 0x78000001, 31],
        ["even_mod_17", 0x1E240, 17],
        ["montgomery_17", 0x1E241, 17],
    ]

    with open(SOURCE_DIR / "big_mod_randomized.json", "w") as f:
        tests = {}
        for test_name, m, bits in params:
            assert math.ceil(math.log2(m)) == bits

            rnd = random.Random(0)

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
