/*****************************************************************
* Name: H.M. Shamalka S. Herath
* Assignment No: 03
* Stu.No: 7657197
* User Id: umherat2
* Course: Comp4140
* Implementing AES for plaintext of 128bit blocks and 128 bit key
* Processes of Encrypting the Plaintext and Decrypting the Cipher text
*****************************************************************/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_BYTES 16
#define Nb 4
#define Nr 10
#define Nk 4
#define SIXTEEN 16

uint8_t sBox[SIXTEEN][SIXTEEN];
uint8_t inv_sBox[SIXTEEN][SIXTEEN];

//read the plain text and key in the files passed in
void readText(uint8_t *temp, char *inFile){
	int i=0;
	char word[100];
	int32_t myInt;
	//char c;
	FILE *fp = fopen(inFile, "r");
	while(fscanf(fp, "%s", word) != EOF){
		//printf("%s\n", word);
		sscanf(word, "%x", &myInt);
		temp[i] = myInt;
		i++;
	}
}

//Initialise the state or key (4x4) assigning elements in 1d array to relevent indexes
void initStateOrKey(uint8_t *temp, uint8_t result[Nb][Nb]){
	int r, c;
	for(r=0; r<4; r++){
		for(c=0; c<4; c++){
			result[r][c] = temp[(r+(4*c))];
		}
	}
}

//Read the file received and initialise the SBox and InvSBox
void createSBox_InvSBox(uint8_t sBox[SIXTEEN][SIXTEEN], char *fileName){
	int i=0, j=0;
	char *hexNum;
	int32_t myInt;
	FILE *file;
	file = fopen(fileName, "r");

	if(file == NULL){
		printf("File %s does not exist!\n", fileName);
		//return 0;
	}

	int size = 100;
	char line[size];
	while(fgets(line, size, file) != NULL){

		hexNum = strtok(line, " ");
		while(hexNum != NULL){
			sscanf(hexNum, "%x", &myInt);
			sBox[i][j] = myInt;
			j++;
			hexNum = strtok(NULL, " ");
		}
		i++;
		j=0;
	}
}

//get the num represent by first 4 bits
int getRowNum(uint8_t num){
	return ((num >> 4) & 0xf);
}

//get the num represent by second 4 bits
int getColNum(uint8_t num){
	return (num & 0xf);
}

//multiply the given num by 2
uint8_t xtime(uint8_t byte){

	uint8_t tempByte = byte << 1;
	if(getRowNum(byte) >= 8){
		tempByte = tempByte ^ 0x1b;
	}
	return tempByte;
}

//Initialise the Round constant values
void getRcon(int32_t *Rcon){
	int i;
	uint8_t temp = 0x01;
	for(i=1; i<11; i++){
		//first << 24
		Rcon[i] = temp << 24;
		temp = xtime(temp);
	}
}

//return the byte specified by n
uint8_t getByte(int n, int32_t temp)
{
	uint8_t byte = (temp >> (n*8)) & 0xff;
	return byte;
}

//multiply given numbers using xtime() and xoring relevent results
uint8_t multiply(uint8_t num1, uint8_t num2){
	int i;
	uint8_t result = 0x00;
	uint8_t multiplier = 0x02;
	uint8_t track = xtime(num1);

	if(num2 == multiplier){
		result = track;
	}else{

		for(i = 0; i<7; i++){
			if((num2 & (multiplier << i)) != 0){
				result = result ^ track;
			}
			track = xtime(track);
		}

	}
	//if num2 is odd num xor with num1
	if(num2 & 0x01){
			result = num1 ^ result;
	}

	return result;
}

//Keyshedule: replace each byte in 4 bytes with the byte in Sbox; row# = 1st 4bits, col# = 2nd 4bits
int32_t subWord(int32_t temp){
	int i, r, c, num = 0;
	uint8_t byte;
	int32_t newTemp = 0x00000000;
	for(i=0; i<4; i++){
		byte = getByte(i, temp);
		r = getRowNum(byte);
		c = getColNum(byte);
		byte = sBox[r][c];
		if(num != 0){
			newTemp = byte << num | newTemp;
		}else{
			newTemp = byte | newTemp;
		}
		num += 8;
	}
	return newTemp;
}

//rotate the word of 32bits to left by 8bits
int32_t rotWord(int32_t temp){
	//test = test << 8 | test >> (32-8);
	int32_t result = temp << 8 | getByte(0, temp >> (32 - 8));
	return result;

}

//append, return 4 seperate bytes together
int32_t appendBytes(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth){
	int32_t result = (first << 24) | (second << 16) | (third << 8) | fourth;
	return result;
}

//code for key schedule, generates keys based on provided master key
void keyExpansion(uint8_t key [Nb][Nb], int32_t *w){

	int i = 0;

	//init Rcon
	int32_t Rcon [11];
	getRcon(Rcon);

	int32_t temp = 0;
	//generating first 4 words
	while(i<Nk){
		w[i] = appendBytes(key[0][i], key[1][i], key[2][i], key[3][i]);
		i++;
	}

	while(i < Nb*(Nr+1)){
		temp = w[i-1];
		if((i % Nk) == 0){
			temp = (subWord(rotWord(temp)) ^ Rcon[i/Nk]);
		}
		w[i] = w[i-Nk] ^ temp;
		i++;
	}

}

//Cipher: replace the byte with relevent byte (row and col indexes specified in given byte) in Sbox
void subByte(uint8_t state[Nb][Nb]){
	int r, c, r1, c1;
	uint8_t byte;

	for(r=0; r<Nb; r++){
		for(c=0; c<Nb; c++){
			byte = state[r][c];
			r1 = getRowNum(byte);
			c1 = getColNum(byte);
			state[r][c] = sBox[r1][c1];
		}
	}
}

//Shift the rows to the left, if row = r, shift r positions to the left
void shiftRows(uint8_t state[Nb][Nb]){
	uint8_t temp;
	int r, c, turn=0;
	for(r=1; r<Nb; r++){
		while(turn < r){
			temp = state[r][0];
			for(c=0; c<Nb-1; c++){
				state[r][c] = state[r][c+1];
			}
			state[r][3] = temp;
			turn++;
		}
		turn = 0;
	}
}

//print the 4x4 array: state
void print(uint8_t array[4][Nb]){
	int r, c;
	for(r=0; r<4; r++){
		for(c=0; c<4; c++){
			printf("%3x  ", array[c][r]);
		}
		printf("%-3s", "");
	}
}

//shift the 4byte to the right by one byte
int32_t shiftRight(int32_t fourBytes){
	//test << 8 | test >> (32-8)
	return (fourBytes >> 8 | fourBytes << (32-8));
}

//get the coeficients to perform mixColumn operation
void getCoEfficients(uint8_t coefficients [Nb][Nb], int32_t temp){
	int i, j;
	for(i=0; i<Nb; i++){
		for(j=0; j<Nb; j++){
			coefficients[i][j] = getByte((3-j), temp);
		}
		temp = shiftRight(temp);
	}
}

//perform matrix and vector multiplication and xor operations to get new vals of same col
void mixColumns(uint8_t state[4][Nb]){
	int i, j, rState=0, cState=0, turn=0;
	uint8_t result = 0x00;
	int32_t temp, hexNum = 0x02030101;
	uint8_t coefficients[Nb][Nb];
	getCoEfficients(coefficients, hexNum);
	//print(coefficients);

	while(turn < Nb) //traverse through columns of state
	{
		temp = appendBytes(state[0][turn], state[1][turn], state[2][turn], state[3][turn]);
		for(i=0; i<Nb; i++){
			for(j=0; j<Nb; j++){
				if(coefficients[i][j] == 0x01){
					result ^= getByte((3-j), temp);
				}else{
					result ^= multiply(coefficients[i][j], getByte((3-j), temp));
				}
			}
			state[rState][cState] = result;
			rState++;
			result = 0x00;
		}
		turn++;
		rState = 0;
		cState++;
	}
}

//xor each byte in the state with relevent bytes in relevent keys
void addRoundKeys(uint8_t state[4][Nb], int32_t *wTemp){
	int i, j;
	int32_t temp;
	for(i=0; i<Nb; i++){
		temp = wTemp[i];
		for(j=0; j<Nb; j++){
			state[j][i] = state[j][i] ^ getByte((3-j), temp);
		}
	}
}

//identify and return relevent generated keys based on the round #
void getRoundKeys(int32_t *w, int32_t *wTemp, int round){
	int i;
	for(i=0; i<Nb; i++){
		wTemp[i] = w[((round*Nb)+i)];
	}
}

//print all keys generated by the keyShedule, 4 in a row
void printKeyShedule(int32_t *w){
	int i;
	for(i=0; i<Nb*(Nr+1); i++){
		if(i!=0 && i%4==0){
			printf("\n");
		}
		printf("%x",w[i]);
		if(i%4!=Nb-1){
			printf(", ");
		}
	}
}

//transfer final or resulted values output array
void generateOutput(uint8_t state[4][Nb], uint8_t *output){
	int r, c;
	for(r=0; r<Nb; r++){
		for(c=0; c<Nb; c++){
			output[(r+(4*c))] = state[r][c];
		}
	}
}

//InvCipher: Shift the rows; shift positions - Nb-r to the left
void invShiftRows(uint8_t state[4][Nb]){
	int r, i, shiftPositions, turn;
	uint8_t temp;
	for(r=1; r<Nb; r++){
		shiftPositions = Nb-r;
		turn = 0;
		while(turn < shiftPositions){
			temp = state[r][0];
			for(i=0; i<Nb-1; i++){
				state[r][i] = state[r][(i+1)];
			}
			turn++;
			state[r][Nb-1] = temp;
		}
	}

}

//InvCipher: replace each byts on state with relevent inv_sBox values specified by the byte
void invSubBytes(uint8_t state[4][Nb]){
	int r, c, r1, c1;
	uint8_t byte;

	for(r=0; r<Nb; r++){
		for(c=0; c<Nb; c++){
			byte = state[r][c];
			r1 = getRowNum(byte);
			c1 = getColNum(byte);
			state[r][c] = inv_sBox[r1][c1];
		}
	}
}

//InvCipher: matrix, vector multiplication and xoring to mix columns
void invMixColumns(uint8_t state[4][Nb]){
	int turn=0, i, j,rState=0, cState=0;
	int32_t hexNum = 0x0e0b0d09, temp;
	uint8_t result = 0x00;
	uint8_t coefficients[Nb][Nb];
	getCoEfficients(coefficients, hexNum);

	while(turn < Nb) //traverse through columns of state
	{
		temp = appendBytes(state[0][turn], state[1][turn], state[2][turn], state[3][turn]);
		for(i=0; i<Nb; i++){
			for(j=0; j<Nb; j++){
				result ^= multiply(coefficients[i][j], getByte((3-j), temp));
			}
			state[rState][cState] = result;
			rState++;
			result = 0x00;
		}
		turn++;
		rState = 0;
		cState++;
	}
}

//perform operations in each round and generated cipher from plaintext, keys
void Cipher(uint8_t *input, uint8_t *output, int32_t *w){

	int round = 0;

	//initialise the state
	uint8_t state[4][Nb];
	initStateOrKey(input, state);

	printf("Key Shedule: \n");
	printKeyShedule(w);
	int32_t wTemp[4];
	getRoundKeys(w, wTemp, round);

	printf("\n\n\nEncryption Process:\n--------------------\n");
	printf("Plain Text:\n");
	print(state);

	addRoundKeys(state, wTemp);

	for(round = 1; round< Nr; round++){
		printf("\n\nRound %d\n--------\n", round);
		print(state);

		subByte(state);
		shiftRows(state);
		mixColumns(state);
		getRoundKeys(w, wTemp, round);
		addRoundKeys(state, wTemp);

	}

	printf("\n\nLast Round\n-----------\n");
	print(state);

	subByte(state);
	//print(state);

	shiftRows(state);
	//print(state);

	getRoundKeys(w, wTemp, round);
	addRoundKeys(state, wTemp);
	generateOutput(state, output);
}

//perform operations in each round and generate plaintext from cipher text
void InvCipher(uint8_t *input, uint8_t *output, int32_t *w){
	int round = Nr;

	//initialise the state
	uint8_t state[4][Nb];
	initStateOrKey(input, state);

	printf("\n\n\nDecryption Process:\n--------------------\n");
	printf("Cipher Text:\n");
	print(state);

	int32_t wTemp[4];
	getRoundKeys(w, wTemp, round);
	addRoundKeys(state, wTemp);

	for(round = Nr-1; round>0; round--){
		invShiftRows(state);
		//print(state);
		invSubBytes(state);
		//print(state);
		printf("\n\nRound %d\n--------\n", round);
		print(state);
		getRoundKeys(w, wTemp, round);
		addRoundKeys(state, wTemp);
		invMixColumns(state);

	}
	round = 0;
	invShiftRows(state);
	invSubBytes(state);
	printf("\n\nRound %d\n--------\n", round);
	print(state);

	getRoundKeys(w, wTemp, round);
	addRoundKeys(state, wTemp);
	generateOutput(state, output);
}

//print the final outputs Cipher and Plaintext
void printOutput(uint8_t *outputC){
	int i , len = Nb*Nb;
	for(i=0; i<len; i++){
		if(i!=0 && i%Nb == 0){
			printf("%-3s", "");
		}
		printf("%3x  ", outputC[i]);
	}

}

int main(int argc, char *argv[]){

	if(argc == 3){

		//createSBox
		createSBox_InvSBox(sBox, "aes_sbox.txt");

		//reat the plaintext, convert each element to hexadecimal
		uint8_t input[NUM_BYTES];
		uint8_t outputC[NUM_BYTES];
		readText(input, argv[1]);

		//read in the key
		uint8_t inKey[NUM_BYTES];
		readText(inKey, argv[2]);
		//init key
		uint8_t key[Nb][Nb];
		initStateOrKey(inKey, key);

		//initialise the w array
		int32_t w[Nb*(Nr+1)];
		keyExpansion(key, w);

		printf("\nPlaintext File Name: %s\nKey File Name: %s\n\n", argv[1], argv[2]);

		//Message Encryption
		//*******************************************

		Cipher(input, outputC, w);
		printf("\n\nCipher Text:\n-------------\n");
		printOutput(outputC);

		//*******************************************

		//Cipher Decryption
		//*******************************************

		createSBox_InvSBox(inv_sBox, "aes_inv_sbox.txt");
		uint8_t outputInvC[4*Nb];
		InvCipher(outputC, outputInvC, w);
		printf("\n\nPlain Text:\n-------------\n");
		printOutput(outputInvC);

		//******************************************

		printf("\n\nEnd of Processing!\n");

	}

	return 0;

}


