#include <gtest/gtest.h>

#include <string>

#include "encrypt_decrypt.hpp"

namespace {

TEST(PasswordRulesTest, AcceptsLowercasePasswordWithMinimumLength) {
  EXPECT_NO_THROW(detail::Password("alongsentencepasswordiseasytoremember"));
}

TEST(PasswordRulesTest, RejectsPasswordThatIsTooShort) {
  EXPECT_THROW(detail::Password("short"), std::runtime_error);
}

TEST(PasswordRulesTest, RejectsPasswordWithUppercaseCharacters) {
  EXPECT_THROW(detail::Password("IfThePasswordIsLongYouDontNeedUpperCase"),
               std::runtime_error);
}

TEST(PasswordRulesTest, RejectsPasswordWithDigitsOrSymbols) {
  EXPECT_THROW(detail::Password("ifthepasswordislongyoudontneed123"),
               std::runtime_error);
  EXPECT_THROW(
      detail::Password("ifthepasswordislongyoudontneedspecialcharachters!"),
      std::runtime_error);
}

// TODO: Add tests

}  // namespace
