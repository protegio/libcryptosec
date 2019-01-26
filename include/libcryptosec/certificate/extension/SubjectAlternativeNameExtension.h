#ifndef SUBJECTALTERNATIVENAMEEXTENSION_H_
#define SUBJECTALTERNATIVENAMEEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/GeneralNames.h>

class SubjectAlternativeNameExtension : public Extension
{
public:
	SubjectAlternativeNameExtension();
	SubjectAlternativeNameExtension(const X509_EXTENSION *ext);
	SubjectAlternativeNameExtension(const SubjectAlternativeNameExtension& ext);
	SubjectAlternativeNameExtension(SubjectAlternativeNameExtension&& ext);

	virtual ~SubjectAlternativeNameExtension();

	SubjectAlternativeNameExtension& operator=(const SubjectAlternativeNameExtension& ext);
	SubjectAlternativeNameExtension& operator=(SubjectAlternativeNameExtension&& ext);

	void setSubjectAltName(const GeneralNames& generalNames);
	const GeneralNames& getSubjectAltName() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab) const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	X509_EXTENSION* getX509Extension() const;

protected:
	GeneralNames subjectAltName;
};

#endif /*SUBJECTALTERNATIVENAMEEXTENSION_H_*/
