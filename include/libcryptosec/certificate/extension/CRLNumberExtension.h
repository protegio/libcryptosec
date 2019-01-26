#ifndef CRLNUMBEREXTENSION_H_
#define CRLNUMBEREXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/BigInteger.h>

#include <openssl/x509.h>

class CRLNumberExtension : public Extension
{
public:
	CRLNumberExtension(const BigInteger& serial);
	CRLNumberExtension(const X509_EXTENSION* ext);

	virtual ~CRLNumberExtension();

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab = "");
	virtual std::string extValue2Xml(const std::string& tab = "");

	void setSerial(unsigned long serial); //TODO
	const BigInteger& getSerial() const; //TODO
	X509_EXTENSION* getX509Extension(); //TODO
	
protected:
	BigInteger serial;
};

#endif /*CRLNUMBEREXTENSION_H_*/
