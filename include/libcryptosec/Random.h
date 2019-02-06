#ifndef RANDOM_H_
#define RANDOM_H_

#include <string>

class ByteArray;

/**
 * @brief Implementa funcionalidades de um Gerador de Números Aleatórios.
 * Esta classe possui apenas métodos estáticos.
 * Antes de gerar dados randômicos deve-se semear o GNA com dados a partir de qualquer fonte.
 * Esta pode ser um arquivo, bytes randômicos ou dados fornecidos por um hardware (através de uma engine). 
 */
class Random
{
public:

	/**
	 * Gera bytes randômicos.
	 * @param nbytes quantidade de bytes a ser gerada.
	 * @return objeto ByteArray que representa bytes randômicos.
	 * @throw RandomException caso função de geração de bytes não esteja implementada ou caso o gerador não tenha sido semeado.
	 */
	static ByteArray bytes(unsigned int nbytes);
	
	/**
	 * Semeia o Gerador de Número Aleatórios com semente.
	 * @param data dados aleatórios utilizados como semente.
	 */
	static void seedData(const ByteArray& data);
	
	/**
	 * Semeia o Gerador de Número Aleatórios com semente a partir de um arquivo.
	 * @param filename caminho para arquivo.
	 * @param nbytes número máximo de bytes a ser lido do conteúdo do arquivo.
	 */
	static void seedFile(const std::string& filename, int nbytes);
	
	/**
	 * Limpa recursos utilizados pelo Gerador de Números Aleatórios.
	 */
	static void cleanSeed();
	
	/**
	 * Verifica se o Gerador de Números Aleatório foi semeado com dados suficientes.
	 * return true se o GNA foi semeado com sucesso, false caso contrário.
	 */
	static bool status();
};

#endif /*RANDOM_H_*/
