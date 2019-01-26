#ifndef KEYUSAGEEXTENSION_H_
#define KEYUSAGEEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <vector>

class KeyUsageExtension : public Extension
{
public:
	enum Usage
	{
		DIGITAL_SIGNATURE = 0,
		NON_REPUDIATION = 1,
		KEY_ENCIPHERMENT = 2,
		DATA_ENCIPHERMENT = 3,
		KEY_AGREEMENT = 4,
		KEY_CERT_SIGN = 5,
		CRL_SIGN = 6,
		ENCIPHER_ONLY = 7,
		DECIPHER_ONLY = 8,
	};

	KeyUsageExtension();
	KeyUsageExtension(const X509_EXTENSION *ext);
	KeyUsageExtension(const KeyUsageExtension& ext);
	KeyUsageExtension(KeyUsageExtension&& ext);

	virtual ~KeyUsageExtension();

	KeyUsageExtension& operator=(const KeyUsageExtension& ext);
	KeyUsageExtension& operator=(KeyUsageExtension&& ext);

	void setUsage(KeyUsageExtension::Usage usage, bool value);
	bool getUsage(KeyUsageExtension::Usage usage) const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	std::string getXmlEncoded(const std::string& tab = "") const;
	std::string extValue2Xml(const std::string& tab = "") const;

	X509_EXTENSION* getX509Extension() const;

	static std::string usage2Name(KeyUsageExtension::Usage usage);

protected:
	std::vector<bool> usages;
};

#endif /*KEYUSAGEEXTENSION_H_*/
