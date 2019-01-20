#include <gtest/gtest.h>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/AsymmetricCipher.h>
#include <libcryptosec/init.h>

#include <iostream>

const std::string testString = "The quick brown fox jumps over the lazy dog";
const unsigned int sizes[] = { 1024, 2048, 4096 };

/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class AsymmetricCipherTest: public ::testing::Test {

protected:

	std::map<int, RSAKeyPair*> rsaKeyPairs;
	std::map<int, ByteArray*> noPaddingTests;

	virtual void SetUp() {
		for (auto size : sizes) {
			rsaKeyPairs[size] = new RSAKeyPair(size);
			noPaddingTests[size] = new ByteArray(size/8);
			memset(noPaddingTests[size]->getDataPointer(), 'A', size/8);
		}
	}

	virtual void TearDown() {
		for (auto size : sizes) {
			delete rsaKeyPairs[size];
			delete noPaddingTests[size];
		}
		rsaKeyPairs.clear();
		noPaddingTests.clear();
	}
};

void testPrint(int keySize, AsymmetricCipher::Padding padding, const ByteArray& originalData,
		const ByteArray& encryptedData, const ByteArray& decryptedData) {
	std::cout << "Key size: " << keySize << std::endl;
	std::cout << "Padding: " << padding << std::endl;
	std::cout << "Original data : " << originalData.toHex(':') << std::endl;
	std::cout << "Encrypted data: " << encryptedData.toHex(':') << std::endl;
	std::cout << "Decrypted data: " << decryptedData.toHex(':') << std::endl << std::endl;
}

/**
 * @brief Testa a função AsymmetricCipher::encrypt e AsymmetricCipher::decrypt para std::string
 */
TEST_F(AsymmetricCipherTest, encryptDecryptString) {
	for (auto size : sizes) {
		auto keyPair = rsaKeyPairs[size];
		auto rsaPublicKey = (RSAPublicKey*) keyPair->getPublicKey();
		auto rsaPrivateKey = (RSAPrivateKey*) keyPair->getPrivateKey();
		for (auto padding : AsymmetricCipher::PaddingList) {
			if (padding != AsymmetricCipher::Padding::NO_PADDING) {
				auto encryptedData = AsymmetricCipher::encrypt(*rsaPublicKey, testString, padding);
				auto decryptedData = AsymmetricCipher::decrypt(*rsaPrivateKey, encryptedData, padding);
				testPrint(size, padding, testString, encryptedData, decryptedData);
				EXPECT_EQ(decryptedData.toString(), testString);
			} else {
				auto encryptedData = AsymmetricCipher::encrypt(*rsaPublicKey, noPaddingTests[size]->toString(), padding);
				auto decryptedData = AsymmetricCipher::decrypt(*rsaPrivateKey, encryptedData, padding);
				testPrint(size, padding, noPaddingTests[size]->toString(), encryptedData, decryptedData);
				EXPECT_EQ(decryptedData.toString(), noPaddingTests[size]->toString());
			}
		}
	}
}

/**
 * @brief Testa as funções AsymmetricCipher::encrypt e AsymmetricCipher::decrypt para ByteArray
 */
TEST_F(AsymmetricCipherTest, encryptDecryptByteArray) {
	ByteArray testByteArray(testString);
	for (auto size : sizes) {
		auto keyPair = rsaKeyPairs[size];
		auto rsaPublicKey = (RSAPublicKey*) keyPair->getPublicKey();
		auto rsaPrivateKey = (RSAPrivateKey*) keyPair->getPrivateKey();
		for (auto padding : AsymmetricCipher::PaddingList) {
			if (padding != AsymmetricCipher::Padding::NO_PADDING) {
				auto encryptedData = AsymmetricCipher::encrypt(*rsaPublicKey, testByteArray, padding);
				auto decryptedData = AsymmetricCipher::decrypt(*rsaPrivateKey, encryptedData, padding);
				testPrint(size, padding, testByteArray, encryptedData, decryptedData);
				EXPECT_TRUE(decryptedData == testByteArray);
			} else {
				auto encryptedData = AsymmetricCipher::encrypt(*rsaPublicKey, *(noPaddingTests[size]), padding);
				auto decryptedData = AsymmetricCipher::decrypt(*rsaPrivateKey, encryptedData, padding);
				testPrint(size, padding, *(noPaddingTests[size]), encryptedData, decryptedData);
				EXPECT_EQ(decryptedData, *(noPaddingTests[size]));
			}
		}
	}
}
