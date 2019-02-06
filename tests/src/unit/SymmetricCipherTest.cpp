#include <gtest/gtest.h>

#include <libcryptosec/RSAKeyPair.h>
#include <libcryptosec/AsymmetricCipher.h>
#include <libcryptosec/Random.h>

#include <iostream>
#include <map>

const std::string testString = "The quick brown fox jumps over the lazy dog";
const unsigned int sizes[] = { 128, 256 };

/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class SymmetricCipherTest: public ::testing::Test {

protected:

	std::map<SymmetricKey::Algorithm, SymmetricKey*> keys;
	std::map<SymmetricKey::Algorithm, ByteArray> ivs;

	virtual void SetUp() {
		for(auto algorithm : SymmetricKey::AlgorithmList) {
			keys[algorithm] = new SymmetricKey(algorithm);
			ivs[algorithm] = Random::bytes(SymmetricKey::getAlgorithmIvSize(algorithm));
		}
	}

	virtual void TearDown() {
		for(auto algorithm : SymmetricKey::AlgorithmList) {
			delete keys[algorithm];
		}
	}

	void testPrint(SymmetricKey::Algorithm algorithm, SymmetricCipher::OperationMode mode,
			const ByteArray& originalData, const ByteArray& encryptedData, const ByteArray& decryptedData) {
		std::cout << "Algorithm     : " << algorithm << std::endl;
		std::cout << "Mode          : " << mode << std::endl;
		std::cout << "Original data : " << originalData.toHex(':') << std::endl;
		std::cout << "Encrypted data: " << encryptedData.toHex(':') << std::endl;
		std::cout << "Decrypted data: " << decryptedData.toHex(':') << std::endl << std::endl;
	}
};

/**
 * @brief Testa a função AsymmetricCipher::encrypt e AsymmetricCipher::decrypt para std::string
 */
TEST_F(SymmetricCipherTest, encryptDecryptString) {
	for (auto algorithm : SymmetricKey::AlgorithmList) {
		SymmetricKey* key = keys[algorithm];
		ByteArray iv = ivs[algorithm];
		for (auto mode : SymmetricCipher::OperationModeList) {
			if (mode == SymmetricCipher::OperationMode::NO_MODE) {
				continue;
			}
			SymmetricCipher cipher(*key, iv, SymmetricCipher::Operation::ENCRYPT, mode);
			SymmetricCipher decipher(*key, iv, SymmetricCipher::Operation::DECRYPT, mode);
			ByteArray *encryptedData = cipher.doFinal(testString);
			ByteArray *decryptedData = decipher.doFinal(*encryptedData);
			this->testPrint(algorithm, mode, ByteArray(testString), *encryptedData, *decryptedData);
			EXPECT_EQ(decryptedData->toString(), testString);
		}
	}
}

/**
 * @brief Testa as funções AsymmetricCipher::encrypt e AsymmetricCipher::decrypt para ByteArray
 */
TEST_F(SymmetricCipherTest, encryptDecryptByteArray) {
	ByteArray originalData(testString);
	for (auto algorithm : SymmetricKey::AlgorithmList) {
		SymmetricKey* key = keys[algorithm];
		ByteArray iv = ivs[algorithm];
		for (auto mode : SymmetricCipher::OperationModeList) {
			if (mode == SymmetricCipher::OperationMode::NO_MODE) {
				continue;
			}
			SymmetricCipher cipher(*key, iv, SymmetricCipher::Operation::ENCRYPT, mode);
			SymmetricCipher decipher(*key, iv, SymmetricCipher::Operation::DECRYPT, mode);
			ByteArray *encryptedData = cipher.doFinal(originalData);
			ByteArray *decryptedData = decipher.doFinal(*encryptedData);
			this->testPrint(algorithm, mode, originalData, *encryptedData, *decryptedData);
			EXPECT_EQ(*decryptedData, originalData);
		}
	}
}
