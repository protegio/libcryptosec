#include <libcryptosec/SymmetricCipher.h>

#include <libcryptosec/exception/OperationException.h>

INITIALIZE_ENUM( SymmetricCipher::OperationMode, 5,
	NO_MODE,
	CBC,
	ECB,
	CFB,
	OFB
);

INITIALIZE_ENUM( SymmetricCipher::Operation, 3,
	NO_OPERATION,
	ENCRYPT,
	DECRYPT,
);

SymmetricCipher::SymmetricCipher()
{
	this->operation = SymmetricCipher::NO_OPERATION;
	this->state = SymmetricCipher::NO_INIT;
	this->mode = SymmetricCipher::NO_MODE;
	this->ctx = EVP_CIPHER_CTX_new();
}

SymmetricCipher::SymmetricCipher(const SymmetricKey &key, const ByteArray& iv, SymmetricCipher::Operation operation, SymmetricCipher::OperationMode mode)
{
	this->operation = SymmetricCipher::NO_OPERATION;
	this->state = SymmetricCipher::NO_INIT;
	this->mode = SymmetricCipher::NO_MODE;
	this->ctx = EVP_CIPHER_CTX_new();
	this->init(key, iv, operation, mode);
}

SymmetricCipher::~SymmetricCipher()
{
	if (this->ctx) {
		EVP_CIPHER_CTX_reset(this->ctx);
		EVP_CIPHER_CTX_free(this->ctx);
	}
}

void SymmetricCipher::init(const SymmetricKey& key, const ByteArray& iv, SymmetricCipher::Operation operation, SymmetricCipher::OperationMode mode)
{
	const EVP_CIPHER *cipher = NULL;

	if(EVP_CIPHER_CTX_cleanup(this->ctx) == 0) {
		throw SymmetricCipherException(SymmetricCipherException::CTX_CLEANUP, "SymmetricCipher::init");
	}

	cipher = SymmetricCipher::getCipher(key.getAlgorithm(), mode);
	const ByteArray& keyData = key.getEncoded();

	EVP_CIPHER_CTX_init(this->ctx);
	int rc = EVP_CipherInit_ex(this->ctx, cipher, NULL, keyData.getConstDataPointer(),
			iv.getConstDataPointer(), (operation == this->ENCRYPT) ? 1 : 0);

	if (!rc) {
		throw SymmetricCipherException(SymmetricCipherException::CTX_INIT, "SymmetricCipher::init");
	}

	this->operation = operation;
	this->state = SymmetricCipher::State::INIT;
	this->mode = mode;

	// TODO: usar pra validação?
	// keylen = EVP_CIPHER_key_length(evp_cipher);
	// ivlen = EVP_CIPHER_iv_length(evp_cipher);
}

ByteArray* SymmetricCipher::update(const std::string& data)
{
	return this->update((unsigned char*) data.c_str(), data.size());
}

ByteArray* SymmetricCipher::update(const ByteArray& data)
{
	return this->update(data.getConstDataPointer(), data.getSize());
}

ByteArray* SymmetricCipher::update(const unsigned char* data, unsigned int size)
{
	int numberOfEncryptedBytes = 0;
	ByteArray *encryptedBuffer = NULL;

	encryptedBuffer = new ByteArray(size + EVP_MAX_BLOCK_LENGTH - 1);
	try {
		this->update(encryptedBuffer->getDataPointer(), &numberOfEncryptedBytes, data, size);
	} catch (SymmetricCipherException& e) {
		delete encryptedBuffer;
		throw e;
	}
	encryptedBuffer->setSize(numberOfEncryptedBytes);

	return encryptedBuffer;
}

void SymmetricCipher::update(unsigned char* out, int* numberOfEncryptedBytes, const unsigned char* data, int size)
{
	int ret = 0;

	if (this->state != SymmetricCipher::State::INIT && this->state != SymmetricCipher::State::UPDATE) {
		throw SymmetricCipherException(SymmetricCipherException::INVALID_STATE, "SymmetricCipher::update");
	}

	if (size <= 0) {
		// TODO porque não retornar um ByteArray vazio?
		throw SymmetricCipherException(SymmetricCipherException::NO_INPUT_DATA, "SymmetricCipher::update");
	}

	ret = EVP_CipherUpdate(this->ctx, out, numberOfEncryptedBytes, data, size);

	if (!ret) {
		// TODO: Ok resetar o cipher?
		this->state = SymmetricCipher::State::NO_INIT;
		throw SymmetricCipherException(SymmetricCipherException::CTX_UPDATE, "SymmetricCipher::update");
	}

	this->state = SymmetricCipher::State::UPDATE;
}

ByteArray* SymmetricCipher::doFinal()
{
	int numberOfEncryptedBytes = 0;
	ByteArray *finalBlock = NULL;

	finalBlock = new ByteArray(EVP_MAX_BLOCK_LENGTH);
	try {
		this->doFinal(finalBlock->getDataPointer(), &numberOfEncryptedBytes);
	} catch (SymmetricCipherException &e) {
		delete finalBlock;
		throw e;
	}
	finalBlock->setSize(numberOfEncryptedBytes);

	return finalBlock;
}

void SymmetricCipher::doFinal(unsigned char* out, int* numberOfEncryptedBytes)
{
	int rc = 0;

	if (this->state != SymmetricCipher::State::UPDATE) {
		throw SymmetricCipherException(SymmetricCipherException::INVALID_STATE, "SymmetricCipher::doFinal");
	}

	rc = EVP_CipherFinal_ex(this->ctx, out, numberOfEncryptedBytes);
	this->state = SymmetricCipher::State::NO_INIT;

	if (!rc) {
		throw SymmetricCipherException(SymmetricCipherException::CTX_FINISH, "SymmetricCipher::doFinal");
	}
}

ByteArray* SymmetricCipher::doFinal(const std::string &data)
{
	int totalSize = 0, numberOfEncryptedBytes = 0;

	if (this->state != SymmetricCipher::State::INIT && this->state != SymmetricCipher::State::UPDATE) {
		throw SymmetricCipherException(SymmetricCipherException::INVALID_STATE, "SymmetricCipher::doFinal");
	}

	ByteArray* encryptedData = new ByteArray(data.size() + 2 * EVP_MAX_BLOCK_LENGTH - 1);
	unsigned char* encryptedDataPointer = encryptedData->getDataPointer();

	this->update(encryptedDataPointer, &numberOfEncryptedBytes, (const unsigned char*) data.c_str(), data.size());
	totalSize = numberOfEncryptedBytes;

	this->doFinal(encryptedDataPointer + numberOfEncryptedBytes, &numberOfEncryptedBytes);
	totalSize += numberOfEncryptedBytes;

	encryptedData->setSize(totalSize);

	return encryptedData;
}

ByteArray* SymmetricCipher::doFinal(const ByteArray &data)
{
	int totalSize = 0, numberOfEncryptedBytes = 0;

	if (this->state != SymmetricCipher::State::INIT && this->state != SymmetricCipher::State::UPDATE) {
		throw SymmetricCipherException(SymmetricCipherException::INVALID_STATE, "SymmetricCipher::doFinal");
	}

	ByteArray* encryptedData = new ByteArray(data.getSize() + 2*EVP_MAX_BLOCK_LENGTH - 1);
	unsigned char* encryptedDataPointer = encryptedData->getDataPointer();

	this->update(encryptedDataPointer, &numberOfEncryptedBytes, data.getConstDataPointer(), data.getSize());
	totalSize = numberOfEncryptedBytes;

	this->doFinal(encryptedDataPointer + numberOfEncryptedBytes, &numberOfEncryptedBytes);
	totalSize += numberOfEncryptedBytes;

	encryptedData->setSize(totalSize);

	return encryptedData;
}

SymmetricCipher::OperationMode SymmetricCipher::getOperationMode()
{
	return this->mode;
}

SymmetricCipher::Operation SymmetricCipher::getOperation()
{
	return this->operation;
}

ASN1_TYPE* SymmetricCipher::getAsn1TypeParameters()
{
	THROW_OPERATION_ERROR_IF(this->state != SymmetricCipher::INIT);

	ASN1_TYPE *parameters = ASN1_TYPE_new();
	int rc = EVP_CIPHER_param_to_asn1(this->ctx, parameters);
	THROW_OPERATION_ERROR_AND_FREE_IF(rc == 0,
			ASN1_TYPE_free(parameters);
	);
	return parameters;
}

std::string SymmetricCipher::getOperationModeName(SymmetricCipher::OperationMode mode)
{
	std::string ret;
	switch (mode)
	{
		case SymmetricCipher::CBC:
			ret = "cbc";
			break;
		case SymmetricCipher::CFB:
			ret = "cfb";
			break;
		case SymmetricCipher::ECB:
			ret = "ecb";
			break;
		case SymmetricCipher::OFB:
			ret = "cbc";
			break;
		case SymmetricCipher::NO_MODE:
			ret = "";
			break;
	}
	return ret;
}

const EVP_CIPHER* SymmetricCipher::getCipher(SymmetricKey::Algorithm algorithm, SymmetricCipher::OperationMode mode)
{
	std::string algName, modeName, cipherName;
	const EVP_CIPHER *cipher = NULL;

	algName = SymmetricKey::getAlgorithmName(algorithm);
	modeName = SymmetricCipher::getOperationModeName(mode);

	if (modeName != "") {
		cipherName = algName + "-" + modeName;
	} else {
		cipherName = algName;
	}

	cipher = EVP_get_cipherbyname(cipherName.c_str());
	if (!cipher) {
		throw SymmetricCipherException(SymmetricCipherException::INVALID_CIPHER, "SymmetricCipher::getCipher");
	}

	return cipher;
}

void SymmetricCipher::loadSymmetricCiphersAlgorithms()
{
	OpenSSL_add_all_ciphers();
}
