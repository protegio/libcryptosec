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

MessageDigest::MessageDigest()
{
	this->state = MessageDigest::NO_INIT;
	this->algorithm = MessageDigest::NO_ALGORITHM;
	this->ctx = EVP_MD_CTX_new();
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algorithm)
{
	int rc;
	const EVP_MD *md = 0;

	this->state = MessageDigest::INIT;
	this->algorithm = algorithm;
	this->ctx = EVP_MD_CTX_new();

	md = MessageDigest::getMessageDigest(this->algorithm);
	rc = EVP_DigestInit_ex(this->ctx, md, NULL);
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::MessageDigest");
	}
}

MessageDigest::MessageDigest(MessageDigest::Algorithm algorithm, Engine &engine)
{
	int rc;
	const EVP_MD *md = 0;

	this->state = MessageDigest::INIT;
	this->algorithm = algorithm;
	this->ctx = EVP_MD_CTX_new();

	md = MessageDigest::getMessageDigest(this->algorithm);
	EVP_MD_CTX_init(this->ctx);

	// TODO: esse cast da engine é ok?
	rc = EVP_DigestInit_ex(this->ctx, md, (ENGINE*) engine.getEngine());
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::MessageDigest");
	}
}

MessageDigest::~MessageDigest()
{
	EVP_MD_CTX_reset(this->ctx);
	EVP_MD_CTX_free(this->ctx);
}

void MessageDigest::init(MessageDigest::Algorithm algorithm)
{
	int rc;
	const EVP_MD *md;
	if (this->state != MessageDigest::NO_INIT){
		EVP_MD_CTX_reset(this->ctx);
	}
	this->algorithm = algorithm;
	md = MessageDigest::getMessageDigest(this->algorithm);
	rc = EVP_DigestInit(this->ctx, md);
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::init");
	}
	this->state = MessageDigest::INIT;
}

void MessageDigest::init(MessageDigest::Algorithm algorithm, Engine &engine)
{
	int rc;
	const EVP_MD *md;
	if (this->state != MessageDigest::NO_INIT){
		EVP_MD_CTX_reset(this->ctx);
	}
	this->algorithm = algorithm;
	md = MessageDigest::getMessageDigest(this->algorithm);
	EVP_MD_CTX_init(this->ctx);

	// TODO: esse cast da engine é ok?
	rc = EVP_DigestInit_ex(this->ctx, md, (ENGINE*) engine.getEngine());
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_INIT, "MessageDigest::init");
	}
	this->state = MessageDigest::INIT;
}

void MessageDigest::update(const ByteArray &data)
{
	int rc;
	if (this->state == MessageDigest::NO_INIT)
	{
		throw InvalidStateException("MessageDigest::update");
	}
	rc = EVP_DigestUpdate(this->ctx, data.getConstDataPointer(), data.getSize());
	if (!rc)
	{
		throw MessageDigestException(MessageDigestException::CTX_UPDATE, "MessageDigest::update");
	}
	this->state = MessageDigest::UPDATE;
}

void MessageDigest::update(const std::string &data)
{
	ByteArray content(data);
	this->update(content);
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

void MessageDigest::doFinal(unsigned char* hash, unsigned int* size) {
	int rc = 0;

	if (this->state == MessageDigest::NO_INIT || this->state == MessageDigest::INIT) {
		throw InvalidStateException("MessageDigest::doFinal");
	}

	rc = EVP_DigestFinal_ex(this->ctx, hash, size);
	EVP_MD_CTX_reset(this->ctx);
	this->state = MessageDigest::NO_INIT;
	if (!rc) {
		throw MessageDigestException(MessageDigestException::CTX_FINISH, "MessageDigest::doFinal");
	}
}

MessageDigest::Algorithm MessageDigest::getAlgorithm()
{
	return this->algorithm;
}

const EVP_MD* MessageDigest::getMessageDigest(MessageDigest::Algorithm algorithm)
{
	const EVP_MD *md;
	md = NULL;
	switch (algorithm)
	{
		case MessageDigest::NO_ALGORITHM:
			throw MessageDigestException("MessageDigest::getMessageDigest");
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
	switch (algorithmNid)
	{
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
    		throw MessageDigestException(MessageDigestException::INVALID_ALGORITHM, "MessageDigest::getMessageDigest");
	}
	return ret;
}

void MessageDigest::loadMessageDigestAlgorithms()
{
	OpenSSL_add_all_digests();
}
