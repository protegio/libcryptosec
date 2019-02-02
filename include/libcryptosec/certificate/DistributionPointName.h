#ifndef DISTRIBUTIONPOINTNAME_H_
#define DISTRIBUTIONPOINTNAME_H_

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "GeneralNames.h"
#include "RDNSequence.h"

#include <libcryptosec/exception/CertificationException.h>

class DistributionPointName
{
public:
	enum Type
	{
		UNDEFINED,
		FULL_NAME,
		RELATIVE_NAME,
	};

	DistributionPointName();
	DistributionPointName(const DIST_POINT_NAME *dpn);

	virtual ~DistributionPointName();
	
	void setNameRelativeToCrlIssuer(const RDNSequence& rdnSequence);
	const RDNSequence& getNameRelativeToCrlIssuer() const;

	void setFullName(const GeneralNames& generalNames);
	const GeneralNames& getFullName() const;

	DistributionPointName::Type getType() const;

	DIST_POINT_NAME* getSslObject() const;

	std::string toXml(const std::string& tab = "") const;

protected:
	GeneralNames fullName;
	RDNSequence relativeName;
	DistributionPointName::Type type;
};

#endif /*DISTRIBUTIONPOINTNAME_H_*/
