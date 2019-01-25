#include <libcryptosec/AsymmetricCipher.h>

#include <libcryptosec/RSAPrivateKey.h>
#include <libcryptosec/RSAPublicKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/AsymmetricCipherException.h>

#include <openssl/evp.h>

INITIALIZE_ENUM( AsymmetricCipher::Padding, 3,
	NO_PADDING,
	PKCS1,
	PKCS1_OAEP
);

ByteArray* AsymmetricCipher::encrypt(RSAPublicKey &key, const ByteArray &data, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	ByteArray *ret = new ByteArray(rsaSize);
	EVP_PKEY *evpPkey = key.getEvpPkey();
	RSA* rsaKey = EVP_PKEY_get0_RSA(evpPkey);

	if (rsaKey == NULL) {
		throw AsymmetricCipherException(AsymmetricCipherException::INVALID_KEY_ALGORITHM, "AsymmetricCipher::encrypt");
	}

	rc = RSA_public_encrypt(data.getSize(), data.getConstDataPointer(), ret->getDataPointer(), rsaKey, paddingValue);
	if (rc == -1 || rc != rsaSize) {
		delete ret;
		throw AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "AsymmetricCipher::encrypt");
	}

	return ret;
}

ByteArray* AsymmetricCipher::encrypt(RSAPublicKey &key, const std::string &data, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	ByteArray *ret = new ByteArray(rsaSize);
	EVP_PKEY *evpPkey = key.getEvpPkey();
	RSA* rsaKey = EVP_PKEY_get0_RSA(evpPkey);

	if (rsaKey == NULL) {
		throw AsymmetricCipherException(AsymmetricCipherException::INVALID_KEY_ALGORITHM, "AsymmetricCipher::encrypt");
	}

	rc = RSA_public_encrypt(data.size(), (const unsigned char *) data.c_str(), ret->getDataPointer(), rsaKey, paddingValue);
	if (rc == -1 || rc != rsaSize) {
		delete ret;
		throw AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "AsymmetricCipher::encrypt");
	}

	return ret;
}

ByteArray* AsymmetricCipher::decrypt(RSAPrivateKey &key, const ByteArray &ciphered, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	ByteArray *ret = NULL;
	EVP_PKEY *evpPkey = key.getEvpPkey();
	RSA* rsaKey = EVP_PKEY_get0_RSA(evpPkey);

	if (rsaKey == NULL) {
		throw AsymmetricCipherException(AsymmetricCipherException::INVALID_KEY_ALGORITHM, "AsymmetricCipher::decrypt");
	}

	ret = new ByteArray(rsaSize);
	rc = RSA_private_decrypt(ciphered.getSize(), ciphered.getConstDataPointer(), ret->getDataPointer(), rsaKey, paddingValue);
	if (rc <= 0) {
		delete ret;
		throw AsymmetricCipherException(AsymmetricCipherException::DECRYPTING_DATA, "AsymmetricCipher::decrypt");
	}
	ret->setSize(rc);

	return ret;
}

int AsymmetricCipher::getPadding(AsymmetricCipher::Padding padding)
{
	int ret = -1;
	switch (padding)
	{
		case AsymmetricCipher::NO_PADDING:
			ret = RSA_NO_PADDING;
			break;
		case AsymmetricCipher::PKCS1:
			ret = RSA_PKCS1_PADDING;
			break;
		case AsymmetricCipher::PKCS1_OAEP:
			ret = RSA_PKCS1_OAEP_PADDING;
			break;
	}
	return ret;
}
