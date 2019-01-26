#include <libcryptosec/NetscapeSPKIBuilder.h>

NetscapeSPKIBuilder::NetscapeSPKIBuilder()
{
	this->netscapeSPKI = NETSCAPE_SPKI_new();
}

NetscapeSPKIBuilder::NetscapeSPKIBuilder(std::string netscapeSPKIBase64)
{
	this->netscapeSPKI = NETSCAPE_SPKI_b64_decode(netscapeSPKIBase64.c_str(), netscapeSPKIBase64.size());
	if (!this->netscapeSPKI)
	{
		throw EncodeException(EncodeException::BASE64_DECODE, "NetscapeSPKIBuilder::NetscapeSPKIBuilder");
	}
}

NetscapeSPKIBuilder::~NetscapeSPKIBuilder()
{
	if (this->netscapeSPKI)
	{
		NETSCAPE_SPKI_free(this->netscapeSPKI);
		this->netscapeSPKI = NULL;
	}
}

std::string NetscapeSPKIBuilder::getBase64Encoded()
{
	char *base64Encoded;
	std::string ret;
	base64Encoded = NETSCAPE_SPKI_b64_encode(this->netscapeSPKI);
	if (!base64Encoded)
	{
		throw EncodeException(EncodeException::BASE64_ENCODE, "NetscapeSPKIBuilder::getBase64Encoded");
	}
	ret = base64Encoded;
	free(base64Encoded);
	return ret;
}

void NetscapeSPKIBuilder::setPublicKey(PublicKey &publicKey)
{
	// TODO: cast ok?
	NETSCAPE_SPKI_set_pubkey(this->netscapeSPKI, (EVP_PKEY*) publicKey.getEvpPkey());
}

PublicKey* NetscapeSPKIBuilder::getPublicKey()
{
	EVP_PKEY *pubKey;
	PublicKey *ret;
	pubKey = NETSCAPE_SPKI_get_pubkey(this->netscapeSPKI);
	if (!pubKey)
	{
		throw NetscapeSPKIException(NetscapeSPKIException::SET_NO_VALUE, "NetscapeSPKIBuilder::getPublicKey");
	}
	try
	{
		ret = new PublicKey(pubKey);
	}
	catch (...)
	{
		EVP_PKEY_free(pubKey);
		throw;
	}
	return ret;
}

void NetscapeSPKIBuilder::setChallenge(std::string challenge)
{
	ASN1_IA5STRING_free(this->netscapeSPKI->spkac->challenge);
	this->netscapeSPKI->spkac->challenge = ASN1_IA5STRING_new();
	ASN1_STRING_set(this->netscapeSPKI->spkac->challenge, challenge.c_str(), challenge.size());
}

std::string NetscapeSPKIBuilder::getChallenge()
{
	std::string ret;
	char *data;
	if (this->netscapeSPKI->spkac->challenge->length > 0)
	{
		/* pedir ao jeandré se é feito uma cópia do conteudo ao atribuir direto ao std::string */
		data = (char *) (this->netscapeSPKI->spkac->challenge->data);
		ret = data;
	}
	else
	{
		ret = "";
	}
	return ret;
}

NetscapeSPKI* NetscapeSPKIBuilder::sign(PrivateKey &privateKey, MessageDigest::Algorithm messageDigest)
{
	// TODO: cast ok?
	int rc = NETSCAPE_SPKI_sign(this->netscapeSPKI, (EVP_PKEY*) privateKey.getEvpPkey(), MessageDigest::getMessageDigest(messageDigest));
	if (!rc) {
		throw NetscapeSPKIException(NetscapeSPKIException::SIGNING_SPKI, "NetscapeSPKIBuilder::sign");
	}
	NetscapeSPKI *ret = new NetscapeSPKI(this->netscapeSPKI);
	this->netscapeSPKI = NETSCAPE_SPKI_new();
	return ret;
}
