#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "output_artifacts.hpp"

TEST(OutputArtifactsTests, RangesParse) {
    auto r = Ranges::parse("-1,3-5,8-");
    ASSERT_TRUE(r.has_value());
    ASSERT_EQ(r.value().size(), 3);
    EXPECT_EQ(r.value()[0].to_string(), "0-1");
    EXPECT_EQ(r.value()[1].to_string(), "3-5");
    EXPECT_EQ(r.value()[2].to_string(), "8-");

    auto r1 = Ranges::parse("-1,,x");
    EXPECT_FALSE(r1.has_value());
}

TEST(OutputArtifactsTests, RangesToString) {
    auto r = Ranges::parse("-1,3-5,8-");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r.value().to_string(), "0-1,3-5,8-");

    Ranges r1 = {};
    EXPECT_EQ(r1.to_string(), "");
}
