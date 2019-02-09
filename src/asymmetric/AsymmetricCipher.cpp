#include <libcryptosec/asymmetric/AsymmetricCipher.h>

#include <libcryptosec/asymmetric/RSAPrivateKey.h>
#include <libcryptosec/asymmetric/RSAPublicKey.h>
#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/OperationException.h>

#include <openssl/evp.h>

INITIALIZE_ENUM( AsymmetricCipher::Padding, 3,
	NO_PADDING,
	PKCS1,
	PKCS1_OAEP
);

ByteArray AsymmetricCipher::encrypt(const RSAPublicKey& key, const ByteArray& data, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	const EVP_PKEY *evpPkey = key.getEvpPkey();

	RSA* rsaKey = EVP_PKEY_get0_RSA((EVP_PKEY*) evpPkey);
	THROW_OPERATION_ERROR_IF(rsaKey == NULL);

	ByteArray ret(rsaSize);
	rc = RSA_public_encrypt(data.getSize(), data.getConstDataPointer(), ret.getDataPointer(), rsaKey, paddingValue);
	THROW_OPERATION_ERROR_IF(rc == -1 || rc != rsaSize);

	return ret;
}

ByteArray AsymmetricCipher::encrypt(const RSAPublicKey& key, const std::string& data, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	const EVP_PKEY *evpPkey = key.getEvpPkey();

	RSA* rsaKey = EVP_PKEY_get0_RSA((EVP_PKEY*) evpPkey);
	THROW_OPERATION_ERROR_IF(rsaKey == NULL);

	ByteArray ret(rsaSize);
	rc = RSA_public_encrypt(data.size(), (const unsigned char *) data.c_str(), ret.getDataPointer(), rsaKey, paddingValue);
	THROW_OPERATION_ERROR_IF(rc == -1 || rc != rsaSize);

	return ret;
}

ByteArray AsymmetricCipher::decrypt(const RSAPrivateKey& key, const ByteArray& ciphered, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	const EVP_PKEY *evpPkey = key.getEvpPkey();

	RSA* rsaKey = EVP_PKEY_get0_RSA((EVP_PKEY*) evpPkey);
	THROW_OPERATION_ERROR_IF(rsaKey == NULL);

	ByteArray ret(rsaSize);
	rc = RSA_private_decrypt(ciphered.getSize(), ciphered.getConstDataPointer(), ret.getDataPointer(), rsaKey, paddingValue);
	THROW_OPERATION_ERROR_IF(rc <= 0);
	ret.setSize(rc);

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
