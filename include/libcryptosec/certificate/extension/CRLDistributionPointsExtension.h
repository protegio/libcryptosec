#ifndef CRLDISTRIBUTIONPOINTSEXTENSION_H_
#define CRLDISTRIBUTIONPOINTSEXTENSION_H_

#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/DistributionPoint.h>

class CRLDistributionPointsExtension : public Extension
{
public:
	CRLDistributionPointsExtension();
	CRLDistributionPointsExtension(const X509_EXTENSION *ext);

	virtual ~CRLDistributionPointsExtension();
	
	void addDistributionPoint(const DistributionPoint& distributionPoint);
	const std::vector<DistributionPoint>& getDistributionPoints() const;

	/**
	 * @deprecated
	 * Retorna o conteudo da extensão em formato XML.
	 * Esta função será substituida por toXml().
	 * */
	virtual std::string getXmlEncoded(const std::string& tab = "") const;
	virtual std::string extValue2Xml(const std::string& tab = "") const;

	virtual X509_EXTENSION* getX509Extension() const;

protected:
	std::vector<DistributionPoint> distributionPoints;
};

#endif /*CRLDISTRIBUTIONPOINTSEXTENSION_H_*/
