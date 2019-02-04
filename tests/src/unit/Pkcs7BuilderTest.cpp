#include <libcryptosec/pkcs7/Pkcs7Builder.h>
#include <libcryptosec/pkcs7/Pkcs7.h>

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <map>

const std::string testString = "The quick brown fox jumps over the lazy dog";

/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class Pkcs7BuilderTest : public ::testing::Test {

protected:
	virtual void SetUp() {
	}

    virtual void TearDown() {
    }

    Pkcs7Builder builder;

    void printTest(MessageDigest::Algorithm algorithm, const ByteArray& data,
    		const ByteArray& expectedHash, const ByteArray& calculatedHash) {
    	std::cout << "Algorithm : " << algorithm << std::endl;
    	std::cout << "Data      : " << data.toHex(':') << std::endl;
    	std::cout << "Expected  : " << expectedHash.toHex(':') << std::endl;
    	std::cout << "Calculated: " << calculatedHash.toHex(':') << std::endl;
    }
};

/**
 * @brief Testa a função EVP_MD* GetMessageDigest(MessageDigest::Algorithm).
 */
TEST_F(Pkcs7BuilderTest, DataMode) {
	std::ostringstream ss;

	builder.initData();
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	std::string extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.clear();

	builder.initData();
	builder.update(ByteArray(testString));
	pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.clear();

	builder.initData();
	builder.update((const unsigned char*) testString.c_str(), testString.size() + 1);
	pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.clear();
}

TEST_F(Pkcs7BuilderTest, DigestedMode) {

}

TEST_F(Pkcs7BuilderTest, EncryptedMode) {

}

TEST_F(Pkcs7BuilderTest, SignedMode) {

}

TEST_F(Pkcs7BuilderTest, SignedModeNoSigner) {

}

TEST_F(Pkcs7BuilderTest, EnvelopedMode) {

}

TEST_F(Pkcs7BuilderTest, EnvelopedModeNoRecipient) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedMode) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedModeNoSigner) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedModeNoRecipient) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedModeNoSignerAndNoRecipient) {

}

TEST_F(Pkcs7BuilderTest, BadStates) {

}

TEST_F(Pkcs7BuilderTest, Reset) {

}

