#include <libcryptosec/MessageDigest.h>

#include <libcryptosec/Engine.h>
#include <libcryptosec/exception/MessageDigestException.h>
#include <libcryptosec/exception/InvalidStateException.h>

 #include <openssl/crypto.h>

INITIALIZE_ENUM( MessageDigest::Algorithm, 10,
	NO_ALGORITHM,
	MD4,
	MD5,
	RIPEMD160,
	SHA,
	SHA1,
	SHA224,
	SHA256,
	SHA384,
	SHA512
);

INITIALIZE_ENUM( MessageDigest::State, 3,
	NO_INIT,
	INIT,
	UPDATE
);

MessageDigest::MessageDigest() :
		algorithm(MessageDigest::NO_ALGORITHM),
		state(MessageDigest::NO_INIT),
		ctx(EVP_MD_CTX_new())
{
	THROW_IF(this->ctx == NULL, MessageDigestException, MessageDigestException::UNKNOWN);
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algorithm) :
		algorithm(algorithm),
		state(MessageDigest::INIT),
		ctx(EVP_MD_CTX_new())
{
	THROW_IF(this->ctx == NULL, MessageDigestException, MessageDigestException::UNKNOWN);
	const EVP_MD *md = MessageDigest::getMessageDigest(this->algorithm);
	int rc = EVP_DigestInit_ex(this->ctx, md, NULL);
	THROW_AND_FREE_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_INIT,
			EVP_MD_CTX_free(this->ctx);
	);
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algorithm, Engine &engine) :
		algorithm(algorithm),
		state(MessageDigest::INIT),
		ctx(EVP_MD_CTX_new())
{
	const EVP_MD *md = MessageDigest::getMessageDigest(this->algorithm);

	// CAST: TODO: esse cast da engine é ok?
	int rc = EVP_DigestInit_ex(this->ctx, md, (ENGINE*) engine.getEngine());
	THROW_AND_FREE_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_INIT,
			EVP_MD_CTX_free(this->ctx);
	);
}

MessageDigest::~MessageDigest()
{
	if (this->ctx == NULL) {
		EVP_MD_CTX_reset(this->ctx);
		EVP_MD_CTX_free(this->ctx);
	}
}

void MessageDigest::init(MessageDigest::Algorithm algorithm)
{
	if (this->state != MessageDigest::NO_INIT) {
		EVP_MD_CTX_reset(this->ctx);
	}

	this->algorithm = algorithm;
	const EVP_MD *md = MessageDigest::getMessageDigest(this->algorithm);

	int rc = EVP_DigestInit(this->ctx, md);
	THROW_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_INIT);
	this->state = MessageDigest::INIT;
}

void MessageDigest::init(MessageDigest::Algorithm algorithm, Engine &engine)
{
	if (this->state != MessageDigest::NO_INIT) {
		EVP_MD_CTX_reset(this->ctx);
	}

	this->algorithm = algorithm;
	const EVP_MD *md = MessageDigest::getMessageDigest(this->algorithm);

	// TODO: esse cast da engine é ok?
	int rc = EVP_DigestInit_ex(this->ctx, md, (ENGINE*) engine.getEngine());
	THROW_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_INIT);
	this->state = MessageDigest::INIT;
}

void MessageDigest::update(const ByteArray &data)
{
	return this->update(data.getConstDataPointer(), data.getSize());
}

void MessageDigest::update(const std::string &data)
{
	return this->update((const unsigned char*) data.c_str(), data.size() + 1);
}

void MessageDigest::update(const unsigned char* data, unsigned int size) {
	THROW_NO_REASON_IF(this->state == MessageDigest::NO_INIT, InvalidStateException);
	int rc = EVP_DigestUpdate(this->ctx, data, size);
	THROW_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_UPDATE);
	this->state = MessageDigest::UPDATE;
}

ByteArray MessageDigest::doFinal()
{
	ByteArray ret(EVP_MAX_MD_SIZE);
	unsigned int size = 0;
	this->doFinal(ret.getDataPointer(), &size);
	ret.setSize(size);
	return ret;
}

ByteArray MessageDigest::doFinal(const ByteArray &data)
{
	this->update(data);
	return this->doFinal();
}

ByteArray MessageDigest::doFinal(const std::string &data)
{
	this->update(data);
	return this->doFinal();
}

ByteArray MessageDigest::doFinal(const unsigned char* data, unsigned int size) {
	this->update(data, size);
	return this->doFinal();
}

void MessageDigest::doFinal(unsigned char* hash, unsigned int* size) {
	THROW_NO_REASON_IF(this->state == MessageDigest::NO_INIT || this->state == MessageDigest::INIT, InvalidStateException);

	int rc = EVP_DigestFinal_ex(this->ctx, hash, size);
	THROW_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_FINISH);

	rc = EVP_MD_CTX_reset(this->ctx);
	THROW_IF(rc == 0, MessageDigestException, MessageDigestException::CTX_FINISH);

	this->state = MessageDigest::NO_INIT;
}

MessageDigest::Algorithm MessageDigest::getAlgorithm() const
{
	return this->algorithm;
}

const EVP_MD* MessageDigest::getMessageDigest(MessageDigest::Algorithm algorithm)
{
	const EVP_MD *md = NULL;
	switch (algorithm) {
		case MessageDigest::NO_ALGORITHM:
			THROW(MessageDigestException, MessageDigestException::INVALID_ALGORITHM);
			break;
		case MessageDigest::MD4:
			md = EVP_md4();
			break;
		case MessageDigest::MD5:
			md = EVP_md5();
			break;
		case MessageDigest::RIPEMD160:
			md = EVP_ripemd160();
			break;
		case MessageDigest::SHA:
			md = EVP_sha1();
			break;
		case MessageDigest::SHA1:
			md = EVP_sha1();
			break;
		case MessageDigest::SHA224:
			md = EVP_sha224();
			break;
		case MessageDigest::SHA256:
			md = EVP_sha256();
			break;
		case MessageDigest::SHA384:
			md = EVP_sha384();
			break;
		case MessageDigest::SHA512:
			md = EVP_sha512();
			break;
	}
	return md;
}

MessageDigest::Algorithm MessageDigest::getMessageDigest(int algorithmNid)
{
	MessageDigest::Algorithm ret;
	switch (algorithmNid) {
		case NID_sha512WithRSAEncryption: case NID_ecdsa_with_SHA512: case NID_sha512:
			ret = MessageDigest::SHA512;
			break;
		case NID_sha384WithRSAEncryption: case NID_ecdsa_with_SHA384: case NID_sha384:
			ret = MessageDigest::SHA384;
			break;
		case NID_sha256WithRSAEncryption: case NID_ecdsa_with_SHA256: case NID_sha256:
			ret = MessageDigest::SHA256;
			break;
		case NID_sha224WithRSAEncryption: case NID_ecdsa_with_SHA224: case NID_sha224:
			ret = MessageDigest::SHA224;
			break;
		case NID_dsaWithSHA1: case NID_sha1WithRSAEncryption: case NID_sha1WithRSA: case NID_ecdsa_with_SHA1: case NID_sha1:
    		ret = MessageDigest::SHA1;
    		break;
    	case NID_md5WithRSAEncryption: case NID_md5WithRSA:case NID_md5:
    		ret = MessageDigest::MD5;
    		break;
    	case NID_md4WithRSAEncryption: case NID_md4:
    		ret = MessageDigest::MD4;
    		break;
    	case NID_ripemd160WithRSA: case NID_ripemd160:
    		ret = MessageDigest::RIPEMD160;
    		break;
    	case NID_shaWithRSAEncryption: case NID_sha:
    		ret = MessageDigest::SHA;
    		break;
    	default:
    		THROW(MessageDigestException, MessageDigestException::INVALID_ALGORITHM);
	}
	return ret;
}
