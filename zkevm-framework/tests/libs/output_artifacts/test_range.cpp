#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "output_artifacts.hpp"

TEST(OutputArtifactsTests, RangeParse) {
    ASSERT_TRUE(Range::parse("1").has_value());
    EXPECT_EQ(Range::parse("1").value().lower, 1);
    EXPECT_EQ(Range::parse("1").value().upper.value(), 1);

    ASSERT_TRUE(Range::parse("1-2").has_value());
    EXPECT_EQ(Range::parse("1-2").value().lower, 1);
    EXPECT_EQ(Range::parse("1-2").value().upper.value(), 2);

    ASSERT_TRUE(Range::parse("1-").has_value());
    EXPECT_EQ(Range::parse("1-").value().lower, 1);
    EXPECT_FALSE(Range::parse("1-").value().upper.has_value());

    ASSERT_TRUE(Range::parse("-1").has_value());
    EXPECT_EQ(Range::parse("-1").value().lower, 0);
    EXPECT_EQ(Range::parse("-1").value().upper.value(), 1);

    ASSERT_TRUE(Range::parse("2-2").has_value());
    EXPECT_EQ(Range::parse("2-2").value().lower, 2);
    EXPECT_EQ(Range::parse("2-2").value().upper.value(), 2);

    EXPECT_FALSE(Range::parse("2-1").has_value());
    EXPECT_FALSE(Range::parse("1--2").has_value());
    EXPECT_FALSE(Range::parse("-").has_value());
    EXPECT_FALSE(Range::parse("abc").has_value());
}

TEST(OutputArtifactsTests, RangeToString) {
    EXPECT_EQ(Range().to_string(), "0-");
    EXPECT_EQ(Range(0).to_string(), "0");
    EXPECT_EQ(Range(1).to_string(), "1");
    EXPECT_EQ(Range(0, 2).to_string(), "0-2");
    EXPECT_EQ(Range(1, 2).to_string(), "1-2");
    EXPECT_EQ(Range(2, 2).to_string(), "2");
    EXPECT_EQ(Range::new_lower(0).to_string(), "0-");
    EXPECT_EQ(Range::new_lower(1).to_string(), "1-");
    EXPECT_EQ(Range::new_upper(0).to_string(), "0");
    EXPECT_EQ(Range::new_upper(1).to_string(), "0-1");
}

TEST(OutputArtifactsTests, RangeConcretize) {
    Range r1;
    ASSERT_TRUE(r1.concrete_range(1).has_value());
    EXPECT_EQ(r1.concrete_range(1).value().first, 0);
    EXPECT_EQ(r1.concrete_range(1).value().second, 1);

    ASSERT_TRUE(r1.concrete_range(0).has_value());
    EXPECT_EQ(r1.concrete_range(0).value().first, 0);
    EXPECT_EQ(r1.concrete_range(0).value().second, 0);

    EXPECT_FALSE(r1.concrete_range(-1).has_value());

    Range r2 = Range::new_upper(1);
    ASSERT_TRUE(r2.concrete_range(2).has_value());
    EXPECT_EQ(r2.concrete_range(2).value().first, 0);
    EXPECT_EQ(r2.concrete_range(2).value().second, 1);

    ASSERT_TRUE(r2.concrete_range(1).has_value());
    EXPECT_EQ(r2.concrete_range(1).value().first, 0);
    EXPECT_EQ(r2.concrete_range(1).value().second, 1);

    EXPECT_FALSE(r2.concrete_range(-1).has_value());

    Range r3 = Range::new_lower(1);
    ASSERT_TRUE(r3.concrete_range(1).has_value());
    EXPECT_EQ(r3.concrete_range(1).value().first, 1);
    EXPECT_EQ(r3.concrete_range(1).value().second, 1);

    EXPECT_FALSE(r3.concrete_range(0).has_value());
}
