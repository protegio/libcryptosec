#include <libcryptosec/pkcs7/Pkcs7Builder.h>
#include <libcryptosec/pkcs7/Pkcs7.h>

#include <libcryptosec/Random.h>
#include <libcryptosec/SymmetricKey.h>

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

#define TEST_INIT_UPDATE_DOFINAL(init_foo, str_data, extract_foo)\
std::ostringstream ss(std::stringstream::binary);\
\
init_foo;\
builder.update(str_data);\
Pkcs7 pkcs7 = builder.doFinal();\
pkcs7.extract_foo(ss);\
std::string extracted = ss.str();\
EXPECT_EQ(extracted, str_data);\
ss.str("");\
\
init_foo;\
pkcs7 = builder.doFinal(testString);\
pkcs7.extract_foo(ss);\
extracted = ss.str();\
EXPECT_EQ(extracted, str_data);\
ss.str("");\
\
init_foo;\
builder.update(ByteArray(str_data));\
pkcs7 = builder.doFinal();\
pkcs7.extract_foo(ss);\
extracted = ss.str();\
EXPECT_EQ(extracted, str_data);\
ss.str("");\
\
init_foo;\
pkcs7 = builder.doFinal(ByteArray(str_data));\
pkcs7.extract_foo(ss);\
extracted = ss.str();\
EXPECT_EQ(extracted, str_data);\
ss.str("");\
\
init_foo;\
builder.update((const unsigned char*) str_data.c_str(), str_data.size());\
pkcs7 = builder.doFinal();\
pkcs7.extract_foo(ss);\
extracted = ss.str();\
EXPECT_EQ(extracted, str_data);\
ss.str("");\
\
init_foo;\
pkcs7 = builder.doFinal((const unsigned char*) str_data.c_str(), str_data.size());\
pkcs7.extract_foo(ss);\
extracted = ss.str();\
EXPECT_EQ(extracted, str_data);\
ss.str("")\

/**
 * @brief Testa a função EVP_MD* GetMessageDigest(MessageDigest::Algorithm).
 */
TEST_F(Pkcs7BuilderTest, DataMode) {
	TEST_INIT_UPDATE_DOFINAL(builder.initData(), testString, extract);
}

TEST_F(Pkcs7BuilderTest, DigestedMode) {
	std::ostringstream ss(std::stringstream::binary);

	builder.initDigested(MessageDigest::SHA1);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	std::string extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");

	builder.initDigested(MessageDigest::SHA1);
	pkcs7 = builder.doFinal(testString);
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");

	builder.initDigested(MessageDigest::SHA1);
	builder.update(ByteArray(testString));
	pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");

	builder.initDigested(MessageDigest::SHA1);
	pkcs7 = builder.doFinal(ByteArray(testString));
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");

	builder.initDigested(MessageDigest::SHA1);
	builder.update((const unsigned char*) testString.c_str(), testString.size());
	pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");

	builder.initDigested(MessageDigest::SHA1);
	pkcs7 = builder.doFinal((const unsigned char*) testString.c_str(), testString.size());
	pkcs7.extract(ss);
	extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");
}

TEST_F(Pkcs7BuilderTest, EncryptedMode) {
	std::ostringstream ss(std::stringstream::binary);

	SymmetricKey key(SymmetricKey::AES_256);
	ByteArray iv = Random::bytes(key.getAlgorithmIvSize());

	builder.initEncrypted(key, iv, SymmetricCipher::CBC);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	std::cerr << pkcs7.getPemEncoded() << std::endl;
	pkcs7.extract(ss);
	std::string extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");
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

