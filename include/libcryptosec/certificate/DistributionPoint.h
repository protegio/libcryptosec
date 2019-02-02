#ifndef DISTRIBUTIONPOINT_H_
#define DISTRIBUTIONPOINT_H_

#include "GeneralNames.h"
#include "DistributionPointName.h"

class DistributionPoint
{
public:
	enum ReasonFlags
	{
		UNUSED = 0,
		KEY_COMPROMISE = 1,
		CA_COMPROMISE = 2,
		AFFILIATION_CHANGED = 3,
		SUPERSEDED = 4,
		CESSATION_OF_OPERATION = 5,
		CERTIFICATE_HOLD = 6,
	};

	DistributionPoint();
	DistributionPoint(const DIST_POINT *distPoint);

	virtual ~DistributionPoint();
	
	void setDistributionPointName(const DistributionPointName& dpn);
	const DistributionPointName& getDistributionPointName() const;

	void setReasonFlag(DistributionPoint::ReasonFlags reason, bool value);
	bool getReasonFlag(DistributionPoint::ReasonFlags reason) const;

	void setCrlIssuer(const GeneralNames& crlIssuer);
	const GeneralNames& getCrlIssuer() const;

	std::string toXml(const std::string& tab = "") const;

	DIST_POINT* getSslObject() const;

	static std::string reasonFlag2Name(DistributionPoint::ReasonFlags reason);

protected:
	DistributionPointName distributionPointName;
	bool reasons[7];
	GeneralNames crlIssuer;
};

#endif /*DISTRIBUTIONPOINT_H_*/
