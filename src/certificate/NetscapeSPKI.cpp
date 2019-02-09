#include <libcryptosec/certificate/NetscapeSPKI.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

#include <string.h>

NetscapeSPKI::NetscapeSPKI(NETSCAPE_SPKI *netscapeSPKI)
{
	this->netscapeSPKI = netscapeSPKI;
}

NetscapeSPKI::NetscapeSPKI(const NETSCAPE_SPKI *netscapeSPKI)
{
	THROW_DECODE_ERROR_IF(netscapeSPKI == NULL);

	char *b64 = NETSCAPE_SPKI_b64_encode((NETSCAPE_SPKI*) netscapeSPKI);
	THROW_DECODE_ERROR_IF(b64 == NULL);

	this->netscapeSPKI = NETSCAPE_SPKI_b64_decode(b64, strlen(b64));
	OPENSSL_free(b64);
	THROW_DECODE_ERROR_IF(this->netscapeSPKI == NULL);
}

NetscapeSPKI::NetscapeSPKI(const std::string& netscapeSPKIBase64) :
		netscapeSPKI(NETSCAPE_SPKI_b64_decode(netscapeSPKIBase64.c_str(), netscapeSPKIBase64.size()))
{
	THROW_DECODE_ERROR_IF(this->netscapeSPKI == NULL);
}

NetscapeSPKI::NetscapeSPKI(const NetscapeSPKI& netscapeSpki) :
		NetscapeSPKI(netscapeSpki.netscapeSPKI)
{
}

NetscapeSPKI::NetscapeSPKI(NetscapeSPKI&& netscapeSPKI) :
		netscapeSPKI(netscapeSPKI.netscapeSPKI)
{
	netscapeSPKI.netscapeSPKI = NULL;
}

NetscapeSPKI::~NetscapeSPKI()
{
	NETSCAPE_SPKI_free(this->netscapeSPKI);
}

NetscapeSPKI& NetscapeSPKI::operator=(const NetscapeSPKI& netscapeSPKI)
{
	if (&netscapeSPKI == this) {
		return *this;
	}

	char *b64 = NETSCAPE_SPKI_b64_encode((NETSCAPE_SPKI*) netscapeSPKI.netscapeSPKI);
	THROW_DECODE_ERROR_IF(b64 == NULL);

	this->netscapeSPKI = NETSCAPE_SPKI_b64_decode(b64, strlen(b64));
	OPENSSL_free(b64);
	THROW_DECODE_ERROR_IF(this->netscapeSPKI == NULL);

	return *this;
}

NetscapeSPKI& NetscapeSPKI::operator=(NetscapeSPKI&& netscapeSPKI)
{
	if (&netscapeSPKI == this) {
		return *this;
	}

	this->netscapeSPKI = netscapeSPKI.netscapeSPKI;
	netscapeSPKI.netscapeSPKI = NULL;

	return *this;
}

std::string NetscapeSPKI::getBase64Encoded() const
{
	char *b64 = NETSCAPE_SPKI_b64_encode(this->netscapeSPKI);
	THROW_DECODE_ERROR_IF(b64 == NULL);

	std::string ret(b64);
	OPENSSL_free(b64);

	return ret;
}

PublicKey NetscapeSPKI::getPublicKey() const
{
	// NETSCAPE_SPKI_get_pubkey uses X509_PUBKEY_get that increments
	// the EVP_PKEY reference count, so we have to free the key after
	// use
	EVP_PKEY *pubKey = NETSCAPE_SPKI_get_pubkey(this->netscapeSPKI);
	THROW_DECODE_ERROR_IF(pubKey == NULL);

	try {
		PublicKey ret(pubKey);
		return ret;
	} catch (...) {
		EVP_PKEY_free(pubKey);
		throw;
	}
}

std::string NetscapeSPKI::getChallenge() const
{
	// TODO: deveriamos lançar a exeção ou retornar uma string vazia?
	THROW_DECODE_ERROR_IF(this->netscapeSPKI->spkac == NULL || this->netscapeSPKI->spkac->challenge == NULL);

	if (this->netscapeSPKI->spkac->challenge->length > 0) {
		std::string ret((char*) this->netscapeSPKI->spkac->challenge->data);
		return ret;
	} else {
		return "";
	}
}

bool NetscapeSPKI::verify() const
{
	PublicKey pubKey = this->getPublicKey();
	int rc = NETSCAPE_SPKI_verify(this->netscapeSPKI, (EVP_PKEY*) pubKey.getEvpPkey());
	return (rc == 0 ? false : true);
}

bool NetscapeSPKI::verify(const PublicKey& publicKey) const
{
	int rc = NETSCAPE_SPKI_verify(this->netscapeSPKI, (EVP_PKEY*) publicKey.getEvpPkey());
	return (rc == 0 ? false : true);
}

bool NetscapeSPKI::isSigned() const
{
	// TODO: lançar exceção ou retornar false?
	THROW_DECODE_ERROR_IF(this->netscapeSPKI->signature == NULL);
	return (this->netscapeSPKI->signature->data) != NULL;
}
