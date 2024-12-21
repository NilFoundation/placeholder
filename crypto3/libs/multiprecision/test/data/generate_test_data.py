#---------------------------------------------------------------------------#
# Copyright (c) 2024 Andrey Nefedov <ioxid@nil.foundation>
#
# Distributed under the Boost Software License, Version 1.0
# See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt
#---------------------------------------------------------------------------#

import random
import math
import json
from pathlib import Path

SOURCE_DIR = Path(__file__).resolve().parent


def generate_comparison_test_data():
    ZERO_PROB = 0.05
    EQ_PROB = 0.1
    TEST_CASES = 1000

    def gen_arg(bits, rnd):
        if rnd.random() < ZERO_PROB:
            return 0
        size = rnd.randint(1, bits)
        result = rnd.randint(0 if size == 1 else 1 << (size - 1), (1 << size) - 1)
        assert result < 2**bits
        return result

    rnd = random.Random(0)

    bits = [[12, 17], [260, 130], [128, 256]]

    with open(SOURCE_DIR / "comparison.json", "w") as f:
        tests = {}
        for a_bits, b_bits in bits:
            cases = []
            for i in range(TEST_CASES):
                a = gen_arg(a_bits, rnd)
                if a < 2 ** b_bits and rnd.random() < EQ_PROB:
                    b = a
                else:
                    b = gen_arg(b_bits, rnd)
                cmp_a_b = -1 if a < b else (0 if a == b else 1)
                cases.append({"a": hex(a), "b": hex(b), "cmp_a_b": cmp_a_b})
            tests[f"test_comparison_{a_bits}_{b_bits}"] = cases
        f.write(json.dumps(tests, indent=4))


def generate_modular_arithmetic_test_data():
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
        ["goldilock", 0xFFFFFFFF00000001, 64],
        ["even_mod_17", 0x1E240, 17],
        ["montgomery_17", 0x1E241, 17],
    ]

    with open(SOURCE_DIR / "modular_arithmetic.json", "w") as f:
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
    generate_comparison_test_data()
    generate_modular_arithmetic_test_data()
