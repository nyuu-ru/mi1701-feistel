/*
 * main.cc
 *
 *  Created on: 21 февр. 2022 г.
 *      Author: unyuu
 */

#include <iostream>
#include <fstream>
#include <cstdint>
#include <random>
#include <algorithm>
#include <utility>
#include <vector>
#include <array>

const char *INPUT_FILENAME  = "input.txt";
const char *CRYPT_FILENAME  = "crypt.txt";
const char *OUTPUT_FILENAME = "output.txt";
const char *KEY1_FILENAME   = "key1.dat";
const char *KEY2_FILENAME   = "key2.dat";

std::mt19937 random_gen;

std::mt19937 init_random()
{
	std::array<uint32_t, 624> seed_data;
	std::random_device rd;
	std::generate(
			std::begin(seed_data),
			std::end(seed_data),
			[&]() { return rd(); } );
	std::seed_seq seed(
			std::begin(seed_data),
			std::end(seed_data));
	return std::mt19937(seed);
}

/*
	Размер блока - 32 бита
	Размер подблока - 16 бит
	Количество раундов - 4
	Шифрующая функция:
		F(x, k) = (x <<< 3) ^ k
 */
constexpr int CIPHER1_ROUNDS = 4;
uint16_t cipher1_func(uint16_t x, uint16_t k)
{
	return ((x << 3) | (x >> 13)) ^ k;
}


void generate_key(const char *filename, size_t size_in_bytes)
{
	std::vector<char> data(size_in_bytes);
	std::generate(std::begin(data), std::end(data),
	              [&](){ return random_gen() & 0xff; });

	std::ofstream keyfile(filename, std::ios::binary);
	keyfile.write(&data[0], size_in_bytes);
	keyfile.close();
}

template <typename KT>
std::vector<KT> load_key(const char *filename)
{
	std::ifstream file(filename,
	                   std::ios::binary | std::ios::ate);
	size_t size = file.tellg();
	file.seekg(0);
	std::vector<KT> result(size);
	file.read(reinterpret_cast<char*>(&result[0]), size);
	file.close();
	return result;
}


// TODO: передать туда алгоритм
template <typename BT, typename ST, typename KT>
void encrypt_file(const char *input_filename,
                  const char *crypt_filename,
                  const std::vector<KT> &key)
{
	std::ifstream input_file(input_filename,
	        std::ios::binary | std::ios::ate);
	std::ofstream crypt_file(crypt_filename, std::ios::binary);
	auto file_size = input_file.tellg();
	input_file.seekg(0);
	auto block_size = sizeof(BT);
	auto blocks = file_size / block_size;
	if (file_size % block_size != 0)
		blocks++;

	uint32_t orig_size = file_size;
	crypt_file.write(reinterpret_cast<char*>(&orig_size),
	        sizeof(orig_size));
	for (typeof (blocks) i = 0; i < blocks; ++i) {
		uint32_t current_block = 0;
		input_file.read(
				reinterpret_cast<char*>(&current_block),
		        sizeof(current_block));

		// Тут будет зашифрование текущего блока

		crypt_file.write(
				reinterpret_cast<char*>(&current_block),
		        sizeof(current_block));
	}
}

template <typename BT, typename ST, typename KT>
void decrypt_file(const char *crypt_filename,
                  const char *output_filename,
                  const std::vector<KT> &key)
{
	std::ifstream crypt_file(crypt_filename,
	        std::ios::binary);
	std::ofstream output_file(output_filename,
	        std::ios::binary);
	uint32_t orig_size;
	crypt_file.read(reinterpret_cast<char*>(&orig_size),
	        sizeof(orig_size));
	auto block_size = sizeof(BT);
	auto blocks = orig_size / block_size;
	if (orig_size % block_size != 0)
		blocks++;

	for (typeof (blocks) i = 0; i < blocks; ++i) {
		uint32_t current_block = 0;
		crypt_file.read(
				reinterpret_cast<char*>(&current_block),
		        sizeof(current_block));

		// Тут будет расшифрование текущего блока

		size_t to_write = block_size;
		if (orig_size < block_size)
			to_write = orig_size;
		output_file.write(
				reinterpret_cast<char*>(&current_block),
		        to_write);
		orig_size -= to_write;
	}
}

int main()
{
	random_gen = init_random();

	generate_key(KEY1_FILENAME,
	             CIPHER1_ROUNDS * sizeof(uint16_t));
	generate_key(KEY2_FILENAME,
	             CIPHER1_ROUNDS * sizeof(uint16_t));

	auto key1 = load_key<uint16_t>(KEY1_FILENAME);

	encrypt_file<uint32_t, uint16_t, uint16_t>(
			INPUT_FILENAME, CRYPT_FILENAME, key1);
	decrypt_file<uint32_t, uint16_t, uint16_t>(
			CRYPT_FILENAME, OUTPUT_FILENAME, key1);

	return 0;
}


