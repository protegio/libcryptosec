#include <gtest/gtest.h>

#include <libcryptosec/Base64.h>
#include <libcryptosec/ByteArray.h>

const std::string testString = "The quick brown fox jumps over the lazy dog";

/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class Base64Test: public ::testing::Test {

protected:

	virtual void SetUp() {
	}

	virtual void TearDown() {
	}

	std::string base64NoPadding = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2ch";
	ByteArray testDataNoPadding = std::string("The quick brown fox jumped over the lazy dog!");

	std::string baseB64OnePading = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2c=";
	ByteArray testDataOnePading = std::string("The quick brown fox jumped over the lazy dog");

	std::string baseB64TwoPading = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2chIQ==";
	ByteArray testDataTwoPading = std::string("The quick brown fox jumped over the lazy dog!!");
};

TEST_F(Base64Test, encode) {
	std::string b64 = Base64::encode(testDataNoPadding);
	ASSERT_EQ(b64, base64NoPadding);

	b64 = Base64::encode(testDataOnePading);
	ASSERT_EQ(b64, baseB64OnePading);

	b64 = Base64::encode(testDataTwoPading);
	ASSERT_EQ(b64, baseB64TwoPading);
}

TEST_F(Base64Test, decode) {
	ByteArray data = Base64::decode(base64NoPadding);
	ASSERT_EQ(data, testDataNoPadding);

	data = Base64::decode(baseB64OnePading);
	ASSERT_EQ(data, testDataOnePading);

	data = Base64::decode(baseB64TwoPading);
	ASSERT_EQ(data, testDataTwoPading);
}
