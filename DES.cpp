/**
 * Title: DES Encyption and Decryption
 * Author: Alex Stephen
 * Date: 08-02-2024
*/
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <cmath>

using namespace std;

string enterHex();
string enterKey();
string enterCipher();
void keyManip(string key);
vector<char> hex2binary(string);
int bin2decimal(vector<char>);
vector<char> dec2binary(int);
string bin2hex(vector<char> binary);
vector<char> permute(vector<char> binaryPT, int init_perm[], int size);
vector<char> shift_left(vector<char>, int numOfShifts);
vector<char> binary_xor(vector<char> rightHS, vector<char> roundKey);
string encrypt(string plainText, map<int, vector<char>> roundKeys);
string decrypt(string plainText, map<int, vector<char>> roundKeys);

map<char, string> char2binary = {{'0', "0000"}, {'1', "0001"}, {'2', "0010"}, {'3', "0011"},
								 {'4', "0100"}, {'5', "0101"}, {'6', "0110"}, {'7', "0111"},
								 {'8', "1000"}, {'9', "1001"}, {'A', "1010"}, {'B', "1011"},
								 {'C', "1100"}, {'D', "1101"}, {'E', "1110"}, {'F', "1111"}};

map<int, string> int2binary = {{0, "0000"}, {1, "0001"}, {2, "0010"}, {3, "0011"},
							   {4, "0100"}, {5, "0101"}, {6, "0110"}, {7, "0111"},
							   {8, "1000"}, {9, "1001"}, {10, "1010"}, {11, "1011"},
							   {12, "1100"}, {13, "1101"}, {14, "1110"}, {15, "1111"}};

map<string, string> binary2string = {{"0000", "0"}, {"0001", "1"}, {"0010", "2"}, {"0011", "3"},
    								 {"0100", "4"}, {"0101", "5"}, {"0110", "6"}, {"0111", "7"},
    								 {"1000", "8"}, {"1001", "9"}, {"1010", "A"}, {"1011", "B"},
    								 {"1100", "C"}, {"1101", "D"}, {"1110", "E"}, {"1111", "F"}};

map<int, vector<char>> binary_round_keys;

//Initial 64 bit PT permutation table. 
int initial_permutaion[] ={58, 50, 42, 34, 26, 18, 10, 2,
						   60, 52, 44, 36, 28, 20, 12, 4,
						   62, 54, 46, 38, 30, 22, 14, 6,
						   64, 56, 48, 40, 32, 24, 16, 8,
						   57, 49, 41, 33, 25, 17, 9, 1,
						   59, 51, 43, 35, 27, 19, 11, 3,
						   61, 53, 45, 37, 29, 21, 13, 5,
						   63, 55, 47, 39, 31, 23, 15, 7};
//Expanded RPT to increase from 32 to 48 bits					   
int exp_d[] = {32, 1, 2, 3, 4, 5, 4, 5,
             6, 7, 8, 9, 8, 9, 10, 11,
             12, 13, 12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21, 20, 21,
             22, 23, 24, 25, 24, 25, 26, 27,
             28, 29, 28, 29, 30, 31, 32, 1};

//56 Bit with each 8th bit removed      
int key_parity[] = {57, 49, 41, 33, 25, 17, 9,
                    1, 58, 50, 42, 34, 26, 18,
                    10, 2, 59, 51, 43, 35, 27,
                    19, 11, 3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12, 4};
//48 Bits
int key_compression[]= {14, 17, 11, 24, 1, 5,
                        3, 28, 15, 6, 21, 10,
                        23, 19, 12, 4, 26, 8,
                        16, 7, 27, 20, 13, 2,
                        41, 52, 31, 37, 47, 55,
                        30, 40, 51, 45, 33, 48,
                        44, 49, 39, 56, 34, 53,
                        46, 42, 50, 36, 29, 32};

                        
//Bit shift table
int shift_table[] = {1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1};

//Straight Permutation
int str_perm[] = {16,  7, 20, 21,
				  29, 12, 28, 17,
				  1, 15, 23, 26,
				  5, 18, 31, 10,
				  2,  8, 24, 14,
				  32, 27,  3,  9,
				  19, 13, 30,  6,
				  22, 11,  4, 25};

//8 Required S_Boxes
int s_boxes[8][4][16] = {{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
					{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
					{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
					{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
			
					{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
					{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
					{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
					{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
			
					{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
					{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
					{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
					{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
			
					{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
					{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
					{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
					{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
			
					{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
					{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
					{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
					{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
			
					{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
					{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
					{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
					{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
			
					{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
					{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
					{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
					{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
			
					{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
					{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
					{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
					{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}};

//Final Permutation
int final_perm[] = {40, 8, 48, 16, 56, 24, 64, 32,
					39, 7, 47, 15, 55, 23, 63, 31,
					38, 6, 46, 14, 54, 22, 62, 30,
					37, 5, 45, 13, 53, 21, 61, 29,
					36, 4, 44, 12, 52, 20, 60, 28,
					35, 3, 43, 11, 51, 19, 59, 27,
					34, 2, 42, 10, 50, 18, 58, 26,
					33, 1, 41, 9, 49, 17, 57, 25};

int main()
{
	int choice;
	string plaintext = "0123456789ABCDEF";
	string key = "133457799BBCDFF1";
	string cipherText;
	bool finished;
	cout << "Welcome to DES Encryption and Decryption" << '\n';
	do {
	cout << "Select 1 for Encryption." << '\n';
	cout << "Select 2 for Decryption." << '\n';
	cin >> choice;



	if (choice == 1) {
			plaintext = enterHex();
			key = enterKey();
			keyManip(key);
			cipherText = encrypt(plaintext, binary_round_keys);
			cout << "ENCRYPTION" << '\n' << '\n';
			cout << "The Cipher text is: " << cipherText << '\n';
			finished = false;
	} else if (choice == 2) {
			cipherText = enterCipher();
			key = enterKey();
			keyManip(key);
			plaintext = decrypt(cipherText, binary_round_keys);
			cout << "DECRYPTION" << '\n' << '\n';
			cout << "The Decrypted Cipher Text is : " << plaintext << '\n'; 
			finished = false;
	}

	} while (finished);
    
	return 0;
}
//Key Manipulation that Returns a Map of Round Keys
void keyManip(string key) {
	vector<char> key_binary = hex2binary(key);

	if (key_binary.size() < 64)
		while (key_binary.size() < 64) {
			key_binary.push_back('0');
		}

	//Parity bits removed
	key_binary = permute(key_binary, key_parity, 56);

	//Splitting up the 56 bit key into Left and Right
	vector<char> left_key;
	vector<char> right_key;
	for (int i = 0; i < key_binary.size(); i++) {
		if (i < 28)
			left_key.push_back(key_binary[i]);
		else
			right_key.push_back(key_binary[i]);
	}

	//Performing 16 Rounds on the Key to obtain the round keys
	vector<char> roundKey;
	for (int i = 0; i < 16; i++) {
		left_key = shift_left(left_key, shift_table[i]);
		right_key = shift_left(right_key, shift_table[i]);
		//Combining Both Strings
		vector<char> combined;
		combined.insert(combined.end(), left_key.begin(), left_key.end());
		combined.insert(combined.end(), right_key.begin(), right_key.end());

		//Compressing the Key into 48 bits
		roundKey = permute(combined, key_compression, 48);

		//Append each round key to a map.
		binary_round_keys.emplace(i, roundKey);
	}
}
//Gets the HEX plaintext from the user
string enterHex() {
	bool done = true;
	string text;
	cout << "Enter the HEX Plaintext (LETTERS MUST BE UPPERCASE): " << '\n';
	while (done) {
		cin >> text;
		if (text.length() <= 16) {
			done = false;
		} else {
			cout << "HEX plaintext was too long!!!" << '\n' << '\n';
		}

	}
	return text;
}
//Gets the HEX Key from the user
string enterKey() {
	bool done = true;
	string text;
	cout << "Enter the HEX Key (LETTERS MUST BE UPPERCASE): " << '\n';
	while (done) {
		cin >> text;
		if (text.length() <= 16) {
			done = false;
		} else {
			cout << "HEX Key text was too long!!!" << '\n' << '\n';
		}

	}
	return text;
}
//Gets the HEX Ciphertext from the user
string enterCipher() {
	bool done = true;
	string text;
	cout << "Enter the HEX CipherText (LETTERS MUST BE UPPERCASE): " << '\n';
	while (done) {
		cin >> text;
		if (text.length() <= 16) {
			done = false;
		} else {
			cout << "HEX CipherText was too long!!!" << '\n' << '\n';
		}

	}
	return text;
}
/**
 * Takes a binary sequence and converts it to hex
 * parameters: Vector<char>, the binary string you wish to convert.
 * Return: string, the converted hex code
*/
string bin2hex(vector<char> binary) {
	string hex, four_bit, hex2;
	vector<string> temp;
	for (int i = 0; i < binary.size(); i++) {
		four_bit += binary[i];
		if (four_bit.length() == 4) {
			temp.push_back(four_bit);
			four_bit = "";
		}
	}
	for (int i = 0; i < temp.size(); i++) {
		hex += binary2string[temp[i]];
	}
	return hex;
}

/**
 * Takes a binary sequence and converts it to an integer
 * paramters: Vector<char>, the binary string you wish to convert.
 * return: int, the decimal value of the desired binary sequence 
*/
int bin2decimal(vector<char> binary) {
	int exponent = binary.size() - 1;
	int val = 0;
	for (int i = 0; i < binary.size(); i++) {
		if (binary[i] == '1')
			val += pow(2, exponent);
		exponent--; 
	}
	return val;
}

/**
 * Takes a decimal number between 0-16 and converts it to binary
 * parameters: int, decimal number to be converted to binary
 * return: vector<char>, the binary sequence in char vector format
*/
vector<char> dec2binary(int decimal) {
	string dec2bin = int2binary[decimal];
	vector<char> temp;
	for (int i = 0; i < dec2bin.size(); i++) {
		char ctext = dec2bin[i];
		temp.push_back(ctext);
		
	}
	return temp;
}

/**
 * Takes a hexidecimal number in the form a string and converts it to binary
 * Parameters: string, the hex number in string format
 * return: vector<char>, the converted hex into binary
*/
vector<char> hex2binary(string s) {
	vector<string> temp;
	vector<char> temp1;
	
	for (int i = 0; i < s.size(); i++) {
		char text = s[i];
		temp.push_back(char2binary[text]);
	}

	for (int i = 0; i < temp.size(); i++) {
		string text = temp[i];
		for (int j = 0; j < text.size(); j++) {
			char ctext = text[j];
			temp1.push_back(ctext);
		}
	}

	return temp1;

}

/**
 * Performs permutation operations on binary sequences in vector<char> format
 * paramters: 
 * 	vector<char>, the binary sequence you wish to permute
 * 	int[], the permation table you wish to manipulate the binary sequence
 * 	int, the size of the permutation table
 * Return: vector<char>, the permuted binary sequence
*/
vector<char> permute(vector<char> binaryPT, int perm[], int size) {
	vector<char> permuted;
    char binary;
    int index;
	for (int i = 0; i < size; i++) {
		index = perm[i] - 1;
        binary = binaryPT[index];
		permuted.push_back(binary);
	}
	return permuted;
}

/**
 * Performs a left shift on a binary sequence
 * Parameters: 
 * 	vector<char>, the binary sequence you wish to left shift
 * 	int, the number of left shifts to perform
 * Return: vector<char>, the left shifted binary sequence
*/
vector<char> shift_left(vector<char> roundString, int numOfShifts) {
    vector<char> temp;
    for (int i = 0; i < numOfShifts; i++) {
        temp.push_back(roundString.front());
        roundString.erase(roundString.begin(), roundString.begin()+1);
        roundString.emplace_back(temp.front());
        temp.pop_back();
    }
    return roundString;
}

/**
 * Performs a DES encryption on a 64 bit Hexadecimal value using a 64 bit key
 * Parameters:
 * 	string, hexadecimal plainText you wish to erncrypt 
 * 	map<int, vector<char>>, a map that pairs the rounds of key manipulation to
 * 	the indicated round key. 
 * Return: string, the CipherText
*/
string encrypt(string plainText, map<int, vector<char>> roundKeys) {
	string cipher;
	vector<char> bin_plainText = hex2binary(plainText);

	if (bin_plainText.size() < 64)
		while (bin_plainText.size() < 64) {
			bin_plainText.push_back('0');
		}

	//Perform IP
	bin_plainText = permute(bin_plainText, initial_permutaion, 64);
	cout << "PlainText After IP: " << bin2hex(bin_plainText) << '\n' << '\n';

	//Split the PT into L0, R0
	vector<char> left, right, right_expanded, swap;
	for (int i = 0; i < bin_plainText.size(); i++) {
	    if (i < 32)
	        left.push_back(bin_plainText[i]);
	    else
	        right.push_back(bin_plainText[i]);
	}
	cout << "ROUND    " << "LeftHS   " << "RightHS  " << "Round Key" << '\n';
	for (int i = 0; i < 16; i++) {
	//Expand R0 from 32-bits to 48-bits
	right_expanded = permute(right, exp_d, 48);

	//XOR Vector
	vector<char> xor_bin;

	xor_bin = binary_xor(right_expanded, binary_round_keys[i]);

	vector<char> s_BoxOutput;
		for (int j = 0; j < 8; j++) {
			int row, col, val;
			vector<char> rows, cols, temp;
			rows.push_back(xor_bin[j*6]);
			rows.push_back(xor_bin[j*6+5]);
			cols.push_back(xor_bin[j*6+1]);
			cols.push_back(xor_bin[j*6+2]);
			cols.push_back(xor_bin[j*6+3]);
			cols.push_back(xor_bin[j*6+4]);
			row = bin2decimal(rows);
			col = bin2decimal(cols);

			val = s_boxes[j][row][col];

			temp = dec2binary(val);
			s_BoxOutput.insert(s_BoxOutput.end(), temp.begin(), temp.end());
		}
	s_BoxOutput = permute(s_BoxOutput, str_perm, 32);

	//XOR left and permuted S_BoxOutput
	left = binary_xor(left, s_BoxOutput);

	//Swap L and R
	if (i!=15) {
	swap = left;
	left = right;
	right = swap;
	}

	//Print Each Round
	cout << "Round: " << i+1;
	cout << " " << bin2hex(left) << " " << bin2hex(right) << " " << bin2hex(binary_round_keys[i])
		 << '\n';

	}
	cout << '\n' << '\n';
	//Combine L and R
	vector<char> final;
	final.insert(final.end(), left.begin(), left.end());
	final.insert(final.end(), right.begin(), right.end());

	//Final Perm
	final = permute(final, final_perm, 64);

	cipher = bin2hex(final);

	return cipher;

}

/**
 * Performs a DES decryption on a 64 bit Hexadecimal value using a 64 bit key
 * Parameters:
 * 	string, hexadecimal plainText you wish to erncrypt 
 * 	map<int, vector<char>>, a map that pairs the rounds of key manipulation to
 * 	the indicated round key. 
 * Return: string, the PlainText
*/
string decrypt(string cipherText, map<int, vector<char>> roundKeys) {
	string cipher;
	vector<char> bin_cipherText = hex2binary(cipherText);

	if (bin_cipherText.size() < 64)
		while (bin_cipherText.size() < 64) {
			bin_cipherText.push_back('0');
		}

	//Perform IP
	bin_cipherText = permute(bin_cipherText, initial_permutaion, 64);
	cout << "CipherText After IP: " << bin2hex(bin_cipherText) << '\n' << '\n';

	//Split the PT into L0, R0
	vector<char> left, right, right_expanded, swap;
	for (int i = 0; i < bin_cipherText.size(); i++) {
	    if (i < 32)
	        left.push_back(bin_cipherText[i]);
	    else
	        right.push_back(bin_cipherText[i]);
	}
	cout << "ROUND    " << "LeftHS   " << "RightHS  " << "Round Key" << '\n';
	for (int i = 0; i < 16; i++) {
	//Expand R0 from 32-bits to 48-bits
	right_expanded = permute(right, exp_d, 48);

	//XOR Vector
	vector<char> xor_bin;

	xor_bin = binary_xor(right_expanded, binary_round_keys[15-i]);

	vector<char> s_BoxOutput;
		for (int j = 0; j < 8; j++) {
			int row, col, val;
			vector<char> rows, cols, temp;
			rows.push_back(xor_bin[j*6]);
			rows.push_back(xor_bin[j*6+5]);
			cols.push_back(xor_bin[j*6+1]);
			cols.push_back(xor_bin[j*6+2]);
			cols.push_back(xor_bin[j*6+3]);
			cols.push_back(xor_bin[j*6+4]);
			row = bin2decimal(rows);
			col = bin2decimal(cols);

			val = s_boxes[j][row][col];

			temp = dec2binary(val);
			s_BoxOutput.insert(s_BoxOutput.end(), temp.begin(), temp.end());
		}
	s_BoxOutput = permute(s_BoxOutput, str_perm, 32);

	//XOR left and permuted S_BoxOutput
	left = binary_xor(left, s_BoxOutput);

	//Swap L and R
	if (i!=15) {
	swap = left;
	left = right;
	right = swap;
	}

	//Print Each Round
	cout << "Round: " << i+1;
	cout << " " << bin2hex(left) << " " << bin2hex(right) << " " << bin2hex(binary_round_keys[15-i])
		 << '\n';

	}
	cout << '\n' << '\n';
	//Combine L and R
	vector<char> final;
	final.insert(final.end(), left.begin(), left.end());
	final.insert(final.end(), right.begin(), right.end());

	//Final Permutation
	final = permute(final, final_perm, 64);

	cipher = bin2hex(final);

	return cipher;

}
/**
 * Performs a binary xor operation on two binary sequences
 * Parameters: vector<char>, Ri and the round key
 * Return: vector<char>, the xor'ed binary sequence
*/
vector<char> binary_xor(vector<char> rightHS, vector<char> roundKey) {
	vector<char> xored;
	for (int i = 0; i < roundKey.size(); i++) {
		if (rightHS[i] == roundKey[i])
			xored.push_back('0');
		else
			xored.push_back('1');
	}
	return xored;
}



