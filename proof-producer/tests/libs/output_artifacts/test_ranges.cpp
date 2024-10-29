#include <gtest/gtest.h>

#include <nil/proof-generator/output_artifacts/output_artifacts.hpp>

using nil::proof_generator::Range;
using nil::proof_generator::Ranges;

TEST(OutputArtifactsTests, RangesToString) {
    Ranges r {{
        Range(0, 1),
        Range(3, 5),
        Range::new_lower(8),
    }};
    EXPECT_EQ(r.to_string(), "0-1 3-5 8-");

    Ranges r1 = {};
    EXPECT_EQ(r1.to_string(), "");
}
