#ifndef SUBJECTALTERNATIVENAMEEXTENSION_H_
#define SUBJECTALTERNATIVENAMEEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>
#include <libcryptosec/certificate/GeneralNames.h>

class SubjectAlternativeNameExtension : public Extension
{
public:
	SubjectAlternativeNameExtension();
	SubjectAlternativeNameExtension(const X509_EXTENSION *ext);

	virtual ~SubjectAlternativeNameExtension();

	void setSubjectAltName(const GeneralNames& generalNames);
	const GeneralNames& getSubjectAltName() const;

	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	GeneralNames subjectAltName;
};

#endif /*SUBJECTALTERNATIVENAMEEXTENSION_H_*/
