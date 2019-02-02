#ifndef GENERALNAMES_H_
#define GENERALNAMES_H_

#include <libcryptosec/certificate/GeneralName.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/x509v3.h>
#include <string>
#include <vector>

class GeneralNames
{
public:
	GeneralNames();
	GeneralNames(const GENERAL_NAMES *generalNames);

	virtual ~GeneralNames();

	void addGeneralName(const GeneralName &generalName);
	const std::vector<GeneralName>& getGeneralNames() const;

	int getNumberOfEntries() const;

	GENERAL_NAMES* getSslObject() const;

	std::string toXml(const std::string& tab = "") const;
protected:
	std::vector<GeneralName> generalNames;
};

#endif /*GENERALNAMES_H_*/
