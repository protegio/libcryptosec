#ifndef ISSUERALTERNATIVENAMEEXTENSION_H_
#define ISSUERALTERNATIVENAMEEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/GeneralNames.h>

class IssuerAlternativeNameExtension : public Extension
{
public:
	IssuerAlternativeNameExtension();
	IssuerAlternativeNameExtension(const X509_EXTENSION* ext);

	virtual ~IssuerAlternativeNameExtension();

	void setIssuerAltName(const GeneralNames& generalNames);
	const GeneralNames& getIssuerAltName() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	GeneralNames issuerAltName;
};

#endif /*ISSUERALTERNATIVENAMEEXTENSION_H_*/
