#ifndef ISSUERALTERNATIVENAMEEXTENSION_H_
#define ISSUERALTERNATIVENAMEEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/GeneralNames.h>

class IssuerAlternativeNameExtension : public Extension
{
public:
	IssuerAlternativeNameExtension();
	IssuerAlternativeNameExtension(X509_EXTENSION *ext);
	virtual ~IssuerAlternativeNameExtension();
	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded();
	std::string getXmlEncoded(std::string tab);
	virtual std::string extValue2Xml(std::string tab = "");
	void setIssuerAltName(GeneralNames &generalNames);
	GeneralNames getIssuerAltName();
	X509_EXTENSION* getX509Extension();
protected:
	GeneralNames issuerAltName;
};

#endif /*ISSUERALTERNATIVENAMEEXTENSION_H_*/
