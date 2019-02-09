#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/asymmetric/RSAKeyPair.h>
#include <libcryptosec/init.h>
#include <libcryptosec/exception/MessageDigestException.h>

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <map>

const std::string testString			= "The quick brown fox jumps over the lazy dog";
const unsigned char MD4_RESULT[] 		= { 0x1b, 0xee, 0x69, 0xa4, 0x6b, 0xa8, 0x11, 0x18, 0x5c, 0x19, 0x47, 0x62, 0xab, 0xae, 0xae, 0x90 };
const unsigned char MD5_RESULT[]		= { 0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6 };
const unsigned char SHA1_RESULT[]		= { 0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12 };
const unsigned char SHA224_RESULT[]		= { 0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0, 0x9a, 0xa2, 0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b, 0xad, 0x91, 0x15, 0x25 };
const unsigned char SHA256_RESULT[]		= { 0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92 };
const unsigned char SHA384_RESULT[]		= { 0xca, 0x73, 0x7f, 0x10, 0x14, 0xa4, 0x8f, 0x4c, 0x0b, 0x6d, 0xd4, 0x3c, 0xb1, 0x77, 0xb0, 0xaf, 0xd9, 0xe5, 0x16, 0x93, 0x67, 0x54, 0x4c, 0x49, 0x40, 0x11, 0xe3, 0x31, 0x7d, 0xbf, 0x9a, 0x50, 0x9c, 0xb1, 0xe5, 0xdc, 0x1e, 0x85, 0xa9, 0x41, 0xbb, 0xee, 0x3d, 0x7f, 0x2a, 0xfb, 0xc9, 0xb1 };
const unsigned char SHA512_RESULT[] 	= { 0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88, 0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39, 0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6, 0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6 };
const unsigned char RIPEMD160_RESULT[]	= { 0x37, 0xf3, 0x32, 0xf6, 0x8d, 0xb7, 0x7b, 0xd9, 0xd7, 0xed, 0xd4, 0x96, 0x95, 0x71, 0xad, 0x67, 0x1c, 0xf9, 0xdd, 0x3b };


/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class MessageDigestTest : public ::testing::Test {

protected:
	virtual void SetUp() {
		this->testVector[MessageDigest::Algorithm::MD4] = ByteArray(MD4_RESULT, sizeof(MD4_RESULT));
		this->testVector[MessageDigest::Algorithm::MD5] = ByteArray(MD5_RESULT, sizeof(MD5_RESULT));
		this->testVector[MessageDigest::Algorithm::SHA] = ByteArray(SHA1_RESULT, sizeof(SHA1_RESULT));
		this->testVector[MessageDigest::Algorithm::SHA1] = ByteArray(SHA1_RESULT, sizeof(SHA1_RESULT));
		this->testVector[MessageDigest::Algorithm::SHA224] = ByteArray(SHA224_RESULT, sizeof(SHA224_RESULT));
		this->testVector[MessageDigest::Algorithm::SHA256] = ByteArray(SHA256_RESULT, sizeof(SHA256_RESULT));
		this->testVector[MessageDigest::Algorithm::SHA384] = ByteArray(SHA384_RESULT, sizeof(SHA384_RESULT));
		this->testVector[MessageDigest::Algorithm::SHA512] = ByteArray(SHA512_RESULT, sizeof(SHA512_RESULT));
		this->testVector[MessageDigest::Algorithm::RIPEMD160] = ByteArray(RIPEMD160_RESULT, sizeof(RIPEMD160_RESULT));
	}

    virtual void TearDown() {
    }

    MessageDigest::Algorithm id2Algorithm(int nid) {
    	switch (nid) {
    	case NID_md4:		return MessageDigest::Algorithm::MD4;
    	case NID_md5:		return MessageDigest::Algorithm::MD5;
    	case NID_ripemd160:	return MessageDigest::Algorithm::RIPEMD160;
    	case NID_sha:		return MessageDigest::Algorithm::SHA;
    	case NID_sha1:		return MessageDigest::Algorithm::SHA1;
    	case NID_sha224:	return MessageDigest::Algorithm::SHA224;
    	case NID_sha256:	return MessageDigest::Algorithm::SHA256;
    	case NID_sha384:	return MessageDigest::Algorithm::SHA384;
    	case NID_sha512:	return MessageDigest::Algorithm::SHA512;
		default:			return MessageDigest::NO_ALGORITHM;
    	}
    }

   static const int mdNidList[];
   std::map<MessageDigest::Algorithm, ByteArray> testVector;

   void printTest(MessageDigest::Algorithm algorithm, const ByteArray& data,
		   const ByteArray& expectedHash, const ByteArray& calculatedHash) {
	   std::cout << "Algorithm : " << algorithm << std::endl;
	   std::cout << "Data      : " << data.toHex(':') << std::endl;
	   std::cout << "Expected  : " << expectedHash.toHex(':') << std::endl;
	   std::cout << "Calculated: " << calculatedHash.toHex(':') << std::endl;
   }
};

const int MessageDigestTest::mdNidList[] = {
		NID_md4,
		NID_md5,
		NID_ripemd160,
		NID_sha,
		NID_sha1,
		NID_sha224,
		NID_sha256,
		NID_sha384,
		NID_sha512
 };

/**
 * @brief Testa a função EVP_MD* GetMessageDigest(MessageDigest::Algorithm).
 */
TEST_F(MessageDigestTest, GetMessageDigestByAlgorithm) {
	for(auto algorithm : MessageDigest::AlgorithmList) {
		if (algorithm != MessageDigest::Algorithm::NO_ALGORITHM) {
			algorithm = (algorithm == MessageDigest::Algorithm::SHA ? MessageDigest::Algorithm::SHA1 : algorithm);
			EXPECT_NO_THROW(MessageDigest::getMessageDigest(algorithm));
			auto md = MessageDigest::getMessageDigest(algorithm);
			EXPECT_EQ(algorithm, id2Algorithm(EVP_MD_nid(md)));
		} else {
			EXPECT_THROW(MessageDigest::getMessageDigest(algorithm), MessageDigestException);
		}
	}
}

/**
 * @brief Testa a função MessageDigest::Algorithm GetMessageDigest(int).
 */
TEST_F(MessageDigestTest, GetMessageDigestByNid) {
	for(auto mdNid : mdNidList) {
		EXPECT_NO_THROW(MessageDigest::getMessageDigest(mdNid));
		auto algorithm = MessageDigest::getMessageDigest(mdNid);
		EXPECT_EQ(algorithm, id2Algorithm(mdNid));
	}
}

/**
 * @brief Testa a função MessageDigest::Algorithm GetMessageDigest(int).
 */
TEST_F(MessageDigestTest, Digest) {
	// removes \0
	ByteArray testByteArray((const unsigned char*) testString.c_str(), testString.size());
	for(auto algorithm : MessageDigest::AlgorithmList) {
		if (algorithm != MessageDigest::Algorithm::NO_ALGORITHM) {
			MessageDigest md(algorithm);
			auto hash = md.doFinal(testByteArray);
			this->printTest(algorithm, testByteArray, testVector[algorithm], hash);
			EXPECT_EQ(hash, testVector[algorithm]);
		} else {
			EXPECT_THROW(MessageDigest::getMessageDigest(algorithm), MessageDigestException);
		}
	}
}


