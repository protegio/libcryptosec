#include <libcryptosec/Hmac.h>

Hmac::Hmac() {
	this->state = Hmac::NO_INIT;
	this->algorithm = MessageDigest::NO_ALGORITHM;
	this->ctx = HMAC_CTX_new();
}

Hmac::Hmac(const std::string& key, MessageDigest::Algorithm algorithm) {
	this->state = Hmac::NO_INIT;
	this->algorithm = MessageDigest::NO_ALGORITHM;
	this->ctx = HMAC_CTX_new();
	this->init(key, algorithm);
}

Hmac::Hmac(const ByteArray& key, MessageDigest::Algorithm algorithm) {
	this->state = Hmac::NO_INIT;
	this->algorithm = MessageDigest::NO_ALGORITHM;
	this->ctx = HMAC_CTX_new();
	this->init(key, algorithm);
}

Hmac::Hmac(const std::string& key, MessageDigest::Algorithm algorithm, Engine &engine) {
	this->state = Hmac::NO_INIT;
	this->algorithm = MessageDigest::NO_ALGORITHM;
	this->ctx = HMAC_CTX_new();
	this->init(key, algorithm, engine);
}

Hmac::Hmac(const ByteArray& key, MessageDigest::Algorithm algorithm, Engine &engine) {
	this->state = Hmac::NO_INIT;
	this->algorithm = MessageDigest::NO_ALGORITHM;
	this->ctx = HMAC_CTX_new();
	this->init(key, algorithm, engine);
}

Hmac::~Hmac() {
	HMAC_CTX_free(this->ctx);
}

void Hmac::init(const ByteArray &key, MessageDigest::Algorithm algorithm) {
	this->init(key.getConstDataPointer(), key.getSize(), algorithm);
}

void Hmac::init(const ByteArray &key, MessageDigest::Algorithm algorithm, Engine &engine) {
	this->init(key.getConstDataPointer(), key.getSize(), algorithm, &engine);
}

void Hmac::init(const std::string& key, MessageDigest::Algorithm algorithm) {
	// TODO: include \0?
	this->init((const unsigned char*) key.c_str(), key.size(), algorithm);
}

void Hmac::init(const std::string& key, MessageDigest::Algorithm algorithm, Engine &engine) {
	// TODO: include \0?
	this->init((const unsigned char*) key.c_str(), key.size(), algorithm, &engine);
}

void Hmac::init(const unsigned char* key, unsigned int size, MessageDigest::Algorithm algorithm, Engine* engine) {
	const EVP_MD *md = MessageDigest::getMessageDigest(algorithm);
	int rc = 0;

	this->algorithm = algorithm;

	rc = HMAC_CTX_reset(this->ctx);
	if(rc == 0) {
		this->state = Hmac::NO_INIT;
		throw HmacException(HmacException::CTX_INIT, "Hmac::init");
	}

	// TODO: esse cast da engine é ok?
	rc = HMAC_Init_ex(this->ctx, (void*) key, size, md, (engine ? (ENGINE*) engine->getEngine() : NULL));
	if (!rc) {
		this->state = Hmac::NO_INIT;
		throw HmacException(HmacException::CTX_INIT, "Hmac::init");
	}

	this->state = Hmac::INIT;
}

void Hmac::update(const ByteArray& data) {
	this->update(data.getConstDataPointer(), data.getSize());
}

void Hmac::update(const std::string& data) {
	this->update((const unsigned char*) data.c_str(), data.size());
}

void Hmac::update(const unsigned char* data, unsigned int size) {
	if (this->state == Hmac::NO_INIT) {
		throw InvalidStateException("Hmac::update");
	}

	int rc = HMAC_Update(this->ctx, data, size);
	if (!rc) {
		throw HmacException(HmacException::CTX_UPDATE, "Hmac::update");
	}

	this->state = Hmac::UPDATE;
}

void Hmac::update(const std::vector<std::string>& data) {
	for(int unsigned i = 0; i < data.size(); i++){
		this->update(data[i]);
	}
}

void Hmac::update(const std::vector<ByteArray>& data) {
	for(int unsigned i = 0; i < data.size(); i++){
		this->update(data[i]);
	}
}

ByteArray* Hmac::doFinal(const ByteArray& data) {
	this->update(data);
	return this->doFinal();
}

ByteArray* Hmac::doFinal(const std::string& data) {
	this->update(data);
	return this->doFinal();
}

ByteArray* Hmac::doFinal() {
	ByteArray *ret = new ByteArray(EVP_MAX_MD_SIZE);
	unsigned int size = 0;

	this->doFinal(ret->getDataPointer(), &size);
	ret->setSize(size);

	return ret;
}

void Hmac::doFinal(unsigned char* hmac, unsigned int* size) {
	if (this->state == Hmac::NO_INIT || this->state == Hmac::INIT) {
		throw InvalidStateException("Hmac::doFinal");
	}

	int rc = HMAC_Final( this->ctx, hmac, size );
	this->state = Hmac::NO_INIT;
	if (!rc) {
		throw HmacException(HmacException::CTX_FINISH, "Hmac::doFinal");
	}
}

