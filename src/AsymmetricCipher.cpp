#include <libcryptosec/AsymmetricCipher.h>

INITIALIZE_ENUM( AsymmetricCipher::Padding, 3,
	NO_PADDING,
	PKCS1,
	PKCS1_OAEP
);

ByteArray AsymmetricCipher::encrypt(RSAPublicKey &key, const ByteArray &data, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	ByteArray ret(rsaSize);
	EVP_PKEY *evpPkey = key.getEvpPkey();
	RSA* rsaKey = EVP_PKEY_get0_RSA(evpPkey);

	rc = RSA_public_encrypt(data.getSize(), data.getConstDataPointer(), ret.getDataPointer(), rsaKey, paddingValue);
	if (rc == -1 || rc != rsaSize)
		throw AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "AsymmetricCipher::encrypt");

	return ret;
}

ByteArray AsymmetricCipher::encrypt(RSAPublicKey &key, const std::string &data, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	ByteArray ret(rsaSize);
	EVP_PKEY *evpPkey = key.getEvpPkey();
	RSA* rsaKey = EVP_PKEY_get0_RSA(evpPkey);

	rc = RSA_public_encrypt(data.size(), (const unsigned char *) data.c_str(), ret.getDataPointer(), rsaKey, paddingValue);
	if (rc == -1 || rc != rsaSize)
		throw AsymmetricCipherException(AsymmetricCipherException::ENCRYPTING_DATA, "AsymmetricCipher::encrypt");

	return ret;
}

ByteArray AsymmetricCipher::decrypt(RSAPrivateKey &key, const ByteArray &ciphered, AsymmetricCipher::Padding padding)
{
	int rc;
	int paddingValue = AsymmetricCipher::getPadding(padding);
	int rsaSize = key.getSize();
	ByteArray ret(rsaSize);
	EVP_PKEY *evpPkey = key.getEvpPkey();
	RSA* rsaKey = EVP_PKEY_get0_RSA(evpPkey);

	rc = RSA_private_decrypt(ciphered.getSize(), ciphered.getConstDataPointer(), ret.getDataPointer(), rsaKey, paddingValue);
	if (rc <= 0)
		throw AsymmetricCipherException(AsymmetricCipherException::DECRYPTING_DATA, "AsymmetricCipher::decrypt");

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
