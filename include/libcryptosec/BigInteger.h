#ifndef BIGINTEGER_H_
#define BIGINTEGER_H_

#include <stdlib.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>

#include <libcryptosec/exception/BigIntegerException.h>
#include "ByteArray.h"

/**
 * @ingroup Util
 */

/**
 * @brief Classe usada para representar números grandes. 
 * A limitação do tamanho do número depende da memória disponível
 */
class BigInteger
{
public:
	/**
	 * Construtor padrão.
	 * Cria um objeto BigInteger com o valor inteiro 0.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 */
	BigInteger();
	
	/**
	 * BigInteger a partir de um estrutura BIGNUM do OpenSSL.
	 * @param bn ponteiro para estrutra constante BIGNUM.
	 * @throw BigIntegerException no caso de erro interno do OpenSSL ao criar o BigInteger.
	 * */
	BigInteger(BIGNUM const* bn);
	
	/**
	 * BigInteger a partir de um tipo primitivo (unsigned long).
	 * @param val valor inteiro.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger. 
	 * */
	BigInteger(long val);
	
	/**
	 * BigInteger a partir de uma estrutura ASN1_INTEGER do OpenSSL.
	 * @param val ponteiro para estrutura ASN1_INTEGER.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(const ASN1_INTEGER* val);
	
	/**
	 * BigInteger a partir de um objeto ByteArray.
	 * @param val referência para objeto constante ByteArray.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger ou devido a um erro interno do OpenSSL.
	 * */
	BigInteger(ByteArray& b);
	
	/**
	 * Construtor de cópia.
	 * @param b referência para um objeto constante BigInteger.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(BigInteger const& b);
	
	/**
	 * BigInteger a partir do string de um número inteiro na base decimal.
	 * @param dec string contendo um número inteiro em base 10.
	 * @throw BigIntegerException no caso de falta de memória ao criar o BigInteger.
	 * */
	BigInteger(std::string dec);
	
	/**
	 * Destrutor padrão
	 * */
	virtual ~BigInteger();
	
	/**
	 * Define o valor inteiro de um BigInteger. Se nenhum valor é passado, define o valor zero.
	 * @param val valor inteiro.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	void setValue(const long val = 0);
	
	/**
	 * Retorna o valor inteiro correspondente do BigInteger.
	 * @return valor inteiro do BigInteger.
	 * @throw BigIntegerException caso o valor do BigInteger não possa ser representado em um unsigned long (overflow).
	 * */
	double getValue() const;
	
	/**
	 * Retorna se o BigInteger é negativo.
	 * @return true se o BigInteger é negativo, false caso contrário.
	 * */
	bool isNegative() const throw();
	
	/**
	 * Retorna estrutura ASN1_INTEGER com o valor do BigInteger.
	 * @return estrutura ASN1_INTEGER.
	 * @throw BigIntegerException no caso de falta de memória ao criar o ASN1_INTEGER.
	 * */
	ASN1_INTEGER* getASN1Value() const;
	
	/**
	 * Retorna ponteiro para um objeto ByteArray com o valor do BigInteger. 
	 * O objeto ByteArray tem codificação mpi (inclui sinal) e deve ser deletado.
	 * @return ponteiro para objeto ByteArray.
	 * @throw BigIntegerException no caso de falta de memória ao criar o ByteArray.
	 * */
	ByteArray* getBinValue() const;
	
	/**
	 * Retorna ponteiro para estrutura constante BIGNUM membro de BigInteger.
	 * @return ponteiro para estrutura constante BIGNUM.
	 * */
	BIGNUM const* getBIGNUM() const throw();
	
	/**
	 * Retorna string com valor do BigInteger em base 16.
	 * @return string com valor inteiro.
	 * */
	std::string toHex() const throw();
	
	/**
	 * Retorna string com valor do BigInteger em base 10.
	 * @return string com valor inteiro.
	 * */	
	std::string toDec() const throw();
	
	/**
	 * Define o valor inteiro em base 16 de um BigInteger. Não utilizar string "0x" para identificar base 16.
	 * @param hex valor inteiro.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	void setHexValue(std::string hex); //nao utilizar "0x"
	
	/**
	* Define o valor inteiro em base 10 de um BigInteger. Não utilizar string "0x" para identificar base 16.
	* @param dec valor inteiro.
	* @throw BigIntegerException no caso de um erro interno do OpenSSL.
	* */
	void setDecValue(std::string dec);
	
	/**
	 * Define um valor inteiro randômico (positivo ou negativo).
	 * @param numBits número de bits do BigInteger. Se nenhum parâmetro é passado, assume-se numBits = 64.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	void setRandValue(int numBits = 64);
	
	/**
	 * Define o sinal do BigInteger.
	 * @param bool true se negativo, false se positivo. Se nenhum parâmetro é passado, assume-se negativo.
	 * */
	void setNegative(bool neg = true) throw();
	
	/**
	 * Retorna o tamanho do valor inteiro do BigInteger em bits.
	 * @return tamanho do BigInteger
	 * */
	int size() const throw();
	
	/**
	 * Soma os valores inteiros entre dois BigIntegers.
	 * @param a referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da soma.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	BigInteger& add(BigInteger const& a);
	
	BigInteger& add(long const a);
	
	/**
	 * Subtração entre os valores inteiros de dois BigIntegers.
	 * @param a referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da subtração.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	BigInteger& sub(BigInteger const& a);
	
	BigInteger& sub(long const a);

	BigInteger& mul(BigInteger const& a);
	BigInteger& mul(long const a);
	BigInteger operator*(BigInteger const& a) const;
	BigInteger operator*(long const c) const;
	
	BigInteger& div(BigInteger const& a);
	BigInteger& div(long const a);
	BigInteger operator/(BigInteger const& a) const;
	BigInteger operator/(long const c) const;
	
	BigInteger& mod(BigInteger const& a);
	BigInteger& mod(long const a);
	BigInteger operator%(BigInteger const& a) const;
	BigInteger operator%(long const c) const;
	
	
	int compare(BigInteger const& a) const throw();
	
	/**
	 * Operador de soma.
	 * @param c referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da soma.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL. 
	 * */
	BigInteger operator+(BigInteger const& c) const;
	BigInteger operator+(long const c) const;
	BigInteger& operator+=(BigInteger const& c);
	BigInteger& operator+=(long const c);
	
	/**
	 * Operador de subtração.
	 * @param c referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger com o resultado da subtração.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL. 
	 * */
	BigInteger operator-(BigInteger const& c) const;
	
	BigInteger operator-(long const c) const;
	
	bool operator==(BigInteger const& c) const throw();
	bool operator==(long const c) const;

	bool operator!=(BigInteger const& c) const throw();
	bool operator!=(long const c) const;
	
	bool operator>(BigInteger const& c) const throw();
	bool operator>(long const c) const;

	bool operator>=(BigInteger const& c) const throw();
	bool operator>=(long const c) const;
	
	bool operator<(BigInteger const& c) const throw();
	bool operator<(long const c) const;

	bool operator<=(BigInteger const& c) const throw();
	bool operator<=(long const c) const;
	
	bool operator!() const throw();
	bool operator||(BigInteger const& c) const throw();
	bool operator||(long const c) const;
	
	bool operator&&(BigInteger const& c) const throw();
	bool operator&&(long const c) const;
	
	
	/**
	 * Operador de atribuição.
	 * @param c referência para objeto constante BigInteger.
	 * @return referência para objeto BigInteger.
	 * @throw BigIntegerException no caso de um erro interno do OpenSSL.
	 * */
	BigInteger& operator=(BigInteger const& c);
	BigInteger& operator=(long const c);
	
	
protected:
	BIGNUM* bigInt;
};

BigInteger operator+(long const c, BigInteger const& d);
BigInteger operator-(long const c, BigInteger const& d);


#endif /*BIGINTEGER_H_*/
