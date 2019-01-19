#include <libcryptosec/SymmetricCipher.h>

SymmetricCipher::SymmetricCipher()
{
	this->operation = SymmetricCipher::NO_OPERATION;
	this->state = SymmetricCipher::NO_INIT;
	this->mode = SymmetricCipher::NO_MODE;
	this->buffer = NULL;
	this->ctx = 0;
}

SymmetricCipher::SymmetricCipher(SymmetricKey &key, SymmetricCipher::Operation operation)
{
	const EVP_CIPHER *cipher;
	ByteArray keyEncoded, *newKey, *iv;
	std::pair<ByteArray*, ByteArray*> keyIv;

	cipher = SymmetricCipher::getCipher(key.getAlgorithm(), SymmetricCipher::CBC);
	keyEncoded = key.getEncoded();

	// TODO: Essa derivação de chave não parece correta, pois torna a classe incompatível com um cifrador padrão.
	keyIv = this->keyToKeyIv(keyEncoded, cipher);
	newKey = keyIv.first;
	iv = keyIv.second;
	
	EVP_CIPHER_CTX_init(this->ctx);
	int rc = EVP_CipherInit_ex(this->ctx, cipher, NULL, newKey->getDataPointer(), iv->getDataPointer(), (operation == this->ENCRYPT)?1:0);
	if (!rc)
	{
		delete newKey;
		delete iv;
		EVP_CIPHER_CTX_cleanup(this->ctx);
		throw SymmetricCipherException(SymmetricCipherException::CTX_INIT, "SymmetricCipher::SymmetricCipher");
	}
	delete newKey;
	delete iv;

	this->operation = operation;
	this->state = SymmetricCipher::INIT;
	this->mode = SymmetricCipher::CBC;
	this->buffer = NULL;
}

SymmetricCipher::SymmetricCipher(SymmetricKey &key, SymmetricCipher::OperationMode mode, SymmetricCipher::Operation operation)
{
	const EVP_CIPHER *cipher;
	ByteArray keyEncoded, *newKey, *iv;
	std::pair<ByteArray*, ByteArray*> keyIv;
	cipher = SymmetricCipher::getCipher(key.getAlgorithm(), mode);
	keyEncoded = key.getEncoded();

	// TODO: Essa derivação de chave não parece correta, pois torna a classe incompatível com um cifrador padrão.
	keyIv = this->keyToKeyIv(keyEncoded, cipher);
	newKey = keyIv.first;
	iv = keyIv.second;
	
	EVP_CIPHER_CTX_reset(this->ctx);
	int rc = EVP_CipherInit_ex(this->ctx, cipher, NULL, newKey->getDataPointer(), iv->getDataPointer(), (operation == this->ENCRYPT)?1:0);
	if (!rc)
	{
		delete newKey;
		delete iv;
		EVP_CIPHER_CTX_reset(this->ctx);
		throw SymmetricCipherException(SymmetricCipherException::CTX_INIT, "SymmetricCipher::SymmetricCipher");
	}
	delete newKey;
	delete iv;

	this->operation = operation;
	this->state = SymmetricCipher::INIT;
	this->mode = mode;
	this->buffer = NULL;
}

SymmetricCipher::~SymmetricCipher()
{
	EVP_CIPHER_CTX_reset(this->ctx);
	EVP_CIPHER_CTX_free(this->ctx);
	if (this->buffer)
	{
		delete this->buffer;
	}
}

void SymmetricCipher::init(SymmetricKey &key, SymmetricCipher::Operation operation)
{
	this->init(key, SymmetricCipher::CBC, operation);
//	EVP_CIPHER_CTX_cleanup(&this->ctx);
//	if (this->buffer)
//	{
//		delete this->buffer;
//		this->buffer = NULL;
//	}
//	const EVP_CIPHER *cipher;
//	ByteArray *keyEncoded, *newKey, *iv;
//	std::pair<ByteArray*, ByteArray*> keyIv;
//	cipher = SymmetricCipher::getCipher(key->getAlgorithm(), SymmetricCipher::CBC);
//	keyEncoded = key->getEncoded();
//	keyIv = this->keyToKeyIv(keyEncoded, cipher);
//	newKey = keyIv.first;
//	iv = keyIv.second;
//	
//	EVP_CIPHER_CTX_init(&this->ctx);
//	int rc = EVP_CipherInit_ex(&this->ctx, cipher, NULL, newKey->getDataPointer(), iv->getDataPointer(), (operation == this->ENCRYPT)?1:0);
//	if (!rc)
//	{
//		delete newKey;
//		delete iv;
//		delete keyEncoded;
//		EVP_CIPHER_CTX_cleanup(&this->ctx);
//		this->state = SymmetricCipher::NO_INIT;
//		throw SymmetricCipherException();
//	}
//	delete newKey;
//	delete iv;
//	delete keyEncoded;
//	this->state = SymmetricCipher::INIT;
}

void SymmetricCipher::init(SymmetricKey &key, SymmetricCipher::OperationMode mode, SymmetricCipher::Operation operation)
{
	EVP_CIPHER_CTX_cleanup(this->ctx);
	if (this->buffer)
	{
		delete this->buffer;
		this->buffer = NULL;
	}
	const EVP_CIPHER *cipher;
	ByteArray keyEncoded, *newKey, *iv;
	std::pair<ByteArray*, ByteArray*> keyIv;
	cipher = SymmetricCipher::getCipher(key.getAlgorithm(), mode);
	keyEncoded = key.getEncoded();

	// TODO: Essa derivação de chave não parece correta, pois torna a classe incompatível com um cifrador padrão.
	keyIv = this->keyToKeyIv(keyEncoded, cipher);
	newKey = keyIv.first;
	iv = keyIv.second;
	
	EVP_CIPHER_CTX_init(this->ctx);
	int rc = EVP_CipherInit_ex(this->ctx, cipher, NULL, newKey->getDataPointer(),
			iv->getDataPointer(), (operation == this->ENCRYPT) ? 1 : 0);

	if (!rc)
	{
		delete newKey;
		delete iv;
		EVP_CIPHER_CTX_cleanup(this->ctx);
		throw SymmetricCipherException(SymmetricCipherException::CTX_INIT, "SymmetricCipher::init");
	}

	delete newKey;
	delete iv;
	this->operation = operation;
	this->state = SymmetricCipher::INIT;
	this->mode = mode;
}

void SymmetricCipher::update(std::string &data)
{
	ByteArray newData;
	newData = ByteArray(data);
	this->update(newData);
}

void SymmetricCipher::update(ByteArray &data)
{
	int ret, totalEncrypted, encrypted;
	ByteArray *newBuffer;
	if (this->state != this->INIT && this->state != this->UPDATE)
	{
		throw InvalidStateException("SymmetricCipher::update");
	}
	if (data.size() <= 0)
	{
		throw SymmetricCipherException(SymmetricCipherException::NO_INPUT_DATA, "SymmetricCipher::update");
	}
	if (this->state == this->INIT)
	{
		totalEncrypted = 0;
	}
	else
	{
		totalEncrypted = this->buffer->size();
	}
	newBuffer = new ByteArray(data.size() + EVP_MAX_BLOCK_LENGTH + totalEncrypted);
	if (this->buffer)
	{
		memcpy(newBuffer->getDataPointer(), this->buffer->getDataPointer(), this->buffer->size());
	}
	ret = EVP_CipherUpdate(this->ctx, &((newBuffer->getDataPointer())[totalEncrypted]), &encrypted, data.getDataPointer(), data.size());
	if (!ret)
	{
		delete newBuffer;
		this->state = this->NO_INIT;
		EVP_CIPHER_CTX_cleanup(this->ctx);
		throw SymmetricCipherException(SymmetricCipherException::CTX_UPDATE, "SymmetricCipher::update");
	}
	totalEncrypted += encrypted;
	if (this->buffer)
	{
		delete this->buffer;
	}
	buffer = new ByteArray(newBuffer->getDataPointer(), totalEncrypted);
	delete newBuffer;
	this->state = this->UPDATE;
}

ByteArray SymmetricCipher::doFinal()
{
	int rc, totalEncrypted = 0, encrypted;
	ByteArray *newBuffer;
	ByteArray ret; 
	if (this->state != this->UPDATE)
	{
		throw InvalidStateException("SymmetricCipher::doFinal");
	}
	this->state = this->NO_INIT;
	newBuffer = new ByteArray(EVP_MAX_BLOCK_LENGTH + EVP_MAX_BLOCK_LENGTH + this->buffer->size());
	memcpy(newBuffer->getDataPointer(), this->buffer->getDataPointer(), this->buffer->size());
	rc = EVP_CipherFinal_ex(this->ctx, &((newBuffer->getDataPointer())[totalEncrypted]), &encrypted);
	if (!rc)
	{
		delete newBuffer;
		throw SymmetricCipherException(SymmetricCipherException::CTX_FINISH, "SymmetricCipher::doFinal");
	}
	totalEncrypted += encrypted;
	ret = ByteArray(newBuffer->getDataPointer(), totalEncrypted);
	delete newBuffer;
	return ret;
}

ByteArray SymmetricCipher::doFinal(std::string &data)
{
	if (this->state != this->INIT && this->state != this->UPDATE)
	{
		throw InvalidStateException("SymmetricCipher::doFinal");
	}
	this->update(data);
	return this->doFinal();
}

ByteArray SymmetricCipher::doFinal(ByteArray &data)
{
	if (this->state != this->INIT && this->state != this->UPDATE)
	{
		throw InvalidStateException("SymmetricCipher::doFinal");
	}
	this->update(data);
	return this->doFinal();
}

SymmetricCipher::OperationMode SymmetricCipher::getOperationMode()
{
	if (this->state == this->NO_INIT)
	{
		throw InvalidStateException("SymmetricCipher::getOperationMode");
	}
	return this->mode;
}

SymmetricCipher::Operation SymmetricCipher::getOperation()
{
	if (this->state == this->NO_INIT)
	{
		throw InvalidStateException("SymmetricCipher::getOperation");
	}
	return this->operation;
}

std::pair<ByteArray*, ByteArray*> SymmetricCipher::keyToKeyIv(ByteArray &key,
		const EVP_CIPHER *cipher, const EVP_MD* md, const unsigned char* salt, int count)
{
	int rc = 0;
	std::pair<ByteArray*, ByteArray*> ret;
	ByteArray *newKey = new ByteArray(EVP_CIPHER_key_length(cipher));
    ByteArray *iv = new ByteArray(EVP_CIPHER_iv_length(cipher));
    rc = EVP_BytesToKey(cipher, md, salt, key.getDataPointer(), key.size(), count, newKey->getDataPointer(), iv->getDataPointer());
	if (rc == 0)
		throw SymmetricCipherException("SymmetricCipher::keyToKeyIv");
    ret.first = newKey;
	ret.second = iv;
	return ret;
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
	const EVP_CIPHER *cipher;
	algName = SymmetricKey::getAlgorithmName(algorithm);
	modeName = SymmetricCipher::getOperationModeName(mode);
	if (modeName != "")
	{
		cipherName = algName + "-" + modeName;
	}
	else
	{
		cipherName = algName;
	}
	cipher = EVP_get_cipherbyname(cipherName.c_str());
	if (!cipher)
	{
		throw SymmetricCipherException(SymmetricCipherException::INVALID_CIPHER, "SymmetricCipher::getCipher");
	}
	return cipher;
}

void SymmetricCipher::loadSymmetricCiphersAlgorithms()
{
	OpenSSL_add_all_ciphers();
}
