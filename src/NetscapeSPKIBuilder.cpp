#include <libcryptosec/NetscapeSPKIBuilder.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

NetscapeSPKIBuilder::NetscapeSPKIBuilder() :
		NetscapeSPKI(NETSCAPE_SPKI_new())
{
}

NetscapeSPKIBuilder::NetscapeSPKIBuilder(const std::string& netscapeSPKIBase64) :
		NetscapeSPKI(netscapeSPKIBase64)
{
}

NetscapeSPKIBuilder::~NetscapeSPKIBuilder()
{
}

void NetscapeSPKIBuilder::setPublicKey(const PublicKey& publicKey)
{
	int rc = NETSCAPE_SPKI_set_pubkey(this->netscapeSPKI, (EVP_PKEY*) publicKey.getEvpPkey());
	THROW_ENCODE_ERROR_IF(rc == 0);
}

void NetscapeSPKIBuilder::setChallenge(const std::string& challenge)
{
	ASN1_IA5STRING *newChallenge =  ASN1_IA5STRING_new();
	THROW_ENCODE_ERROR_IF(newChallenge == NULL);

	if (this->netscapeSPKI->spkac->challenge) {
		ASN1_IA5STRING_free(this->netscapeSPKI->spkac->challenge);
	}

	this->netscapeSPKI->spkac->challenge = newChallenge;

	int rc = ASN1_STRING_set(this->netscapeSPKI->spkac->challenge, challenge.c_str(), challenge.size());
	THROW_ENCODE_ERROR_IF(rc == 0);
	// Não precisamos desalocar this->netscapeSPKI->spkac->challenge
}

NetscapeSPKI NetscapeSPKIBuilder::sign(const PrivateKey& privateKey, MessageDigest::Algorithm messageDigest)
{
	const EVP_MD *md = MessageDigest::getMessageDigest(messageDigest);
	int rc = NETSCAPE_SPKI_sign(this->netscapeSPKI, (EVP_PKEY*) privateKey.getEvpPkey(), md);
	THROW_DECODE_ERROR_IF(rc == 0);
	NetscapeSPKI ret((const NETSCAPE_SPKI*) this->netscapeSPKI);
	return ret;
}
