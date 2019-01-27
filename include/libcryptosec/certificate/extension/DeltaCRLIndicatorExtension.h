#ifndef DELTACRLINDICATOREXTENSION_H_
#define DELTACRLINDICATOREXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/BigInteger.h>

class DeltaCRLIndicatorExtension : public Extension
{
public:
	DeltaCRLIndicatorExtension(const BigInteger& baseCrlNumber = 0);
	DeltaCRLIndicatorExtension(const X509_EXTENSION* ext);

	virtual ~DeltaCRLIndicatorExtension();

	void setSerial(const BigInteger& serial);
	const BigInteger& getSerial() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	BigInteger baseCrlNumber;
};

#endif /*DELTACRLINDICATOREXTENSION_H_*/
