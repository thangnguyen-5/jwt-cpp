#include <gtest/gtest.h>
#include "include/jwt-cpp/jwt.h"

TEST(TokenFormatTest, MissingDot) {
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9"), std::invalid_argument);
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9"), std::invalid_argument);
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9."), std::invalid_argument);
}

TEST(TokenFormatTest, InvalidChar) {
	ASSERT_THROW(jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0().eyJpc3MiOiJhdXRoMCJ9."), std::runtime_error);
}

TEST(TokenFormatTest, InvalidJSON) {
	ASSERT_THROW(jwt::decode("YXsiYWxnIjoibm9uZSIsInR5cCI6IkpXUyJ9YQ.eyJpc3MiOiJhdXRoMCJ9."), std::runtime_error);
}

TEST(TokenFormatTest, MissingDotErrorCode) {
	std::error_code ec;
	ASSERT_EQ(nullptr, jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9", ec));
	ASSERT_TRUE(ec);
	ASSERT_EQ(jwt::error::decode_error_category(), ec.category());
	ASSERT_EQ(static_cast<int>(jwt::error::decode_error::invalid_token_format), ec.value());
	ec.clear();

	ASSERT_EQ(nullptr, jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0.eyJpc3MiOiJhdXRoMCJ9", ec));
	ASSERT_TRUE(ec);
	ASSERT_EQ(jwt::error::decode_error_category(), ec.category());
	ASSERT_EQ(static_cast<int>(jwt::error::decode_error::invalid_token_format), ec.value());
	ec.clear();

	ASSERT_EQ(nullptr, jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn0eyJpc3MiOiJhdXRoMCJ9.", ec));
	ASSERT_TRUE(ec);
	ASSERT_EQ(jwt::error::decode_error_category(), ec.category());
	ASSERT_EQ(static_cast<int>(jwt::error::decode_error::invalid_token_format), ec.value());
	ec.clear();
}

TEST(TokenFormatTest, InvalidCharErrorCode) {
	std::error_code ec;
	ASSERT_EQ(nullptr, jwt::decode("eyJhbGciOiJub25lIiwidHlwIjoiSldTIn(.eyJpc3MiOiJhdXRoMCJ9.", ec));
	ASSERT_TRUE(ec);
	ASSERT_EQ(jwt::error::base64_error_category(), ec.category());
	ASSERT_EQ(static_cast<int>(jwt::error::base64_error::invalid_input_char_not_in_alphabet), ec.value());
	ec.clear();
}

TEST(TokenFormatTest, InvalidJSONErrorCode) {
	std::error_code ec;
	ASSERT_EQ(nullptr, jwt::decode("YXsiYWxnIjoibm9uZSIsInR5cCI6IkpXUyJ9YQ.eyJpc3MiOiJhdXRoMCJ9.", ec));
	ASSERT_TRUE(ec);
	ASSERT_EQ(jwt::error::decode_error_category(), ec.category());
	ASSERT_EQ(static_cast<int>(jwt::error::decode_error::invalid_json), ec.value());
	ec.clear();
}