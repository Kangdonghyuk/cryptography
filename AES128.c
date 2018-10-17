/*  ======================================================================== *

                                    주 의 사 항


    1. 구현은 다양한 방식으로 이뤄질 수 있음
    2. AES128(...) 함수의 호출과 리턴이 여러번 반복되더라도 메모리 누수가 생기지 않게 함
    3. AddRoundKey 함수를 구현할 때에도 파라미터 rKey는 사전에 선언된 지역 배열을 가리키도록 해야 함
       (정확한 구현을 위해서는 포인터 개념의 이해가 필요함)
    4. 배열의 인덱스 계산시 아래에 정의된 KEY_SIZE, ROUNDKEY_SIZE, STATE_SIZE를 이용해야 함
       (상수 그대로 사용하면 안됨. 예로, 4, 16는 안되고 KEY_SIZE/4, STATE_SIZE로 사용해야 함)

 *  ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "AES128.h"

#define KEY_SIZE 16
#define ROUNDKEY_SIZE 176
#define STATE_SIZE 16
#define WORD_SIZE STATE_SIZE/4

/* 기타 필요한 전역 변수 추가 선언 */
BYTE Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };
BYTE sbox[256] = {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F
BYTE insbox[256];
BYTE baseMatrix[4][4] = {
    {2, 3, 1, 1},
    {1, 2, 3, 1}, 
    {1, 1, 2, 3}, 
    {3, 1, 1, 2}
};
BYTE baseInvMatrix[4][4] = {
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d}, 
    {0x0d, 0x09, 0x0e, 0x0b}, 
    {0x0b, 0x0d, 0x09, 0x0e}
};

BYTE getSBoxValue(int num, int mode)
{
    int index;

    for(index = 0; index < 256; index++)
        insbox[sbox[index]] = index;
    if(mode == ENC)
        return sbox[num];
    else if(mode == DEC)
        return insbox[num];
    return sbox[num];
}

void matrixShift(BYTE * matrix, int start) {
    BYTE temp_matrix[4];
    int index = 0, copyIndex = start * 4 + start;

    for(index = 0; index < WORD_SIZE; index++) {
        temp_matrix[index] = *(matrix+copyIndex);
        copyIndex+=4;
        if(copyIndex >= STATE_SIZE)
            copyIndex = start;
    }
    copyIndex = start;
    for(index = 0; index < WORD_SIZE; index++) {
        *(matrix+copyIndex) = temp_matrix[index];
        copyIndex+=4;
    }
}

#define carryProcess(matrix)   ((matrix << 1) ^ (((matrix >> 7) & 1) * 0x1b))
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * carryProcess(x)) ^ ((y>>2 & 1) * carryProcess(carryProcess(x))) ^ ((y>>3 & 1) * carryProcess(carryProcess(carryProcess(x)))) ^ ((y>>4 & 1) * carryProcess(carryProcess(carryProcess(carryProcess(x))))))

BYTE getUnitMultiplication(BYTE base, BYTE act) {
    if(base == 2)
        act = carryProcess(act);
    else if(base == 3)
        act = act ^ carryProcess(act);
    else if(base >= 0x09)
        act = Multiply(act, base);
    return act;
}
void matrixMultiplication(BYTE * matrix, BYTE argMatrix[4][4]) {
    BYTE resultMatrix[16];
    BYTE calculateMatrix[4][4];
    int copyIndex;
    int calculateRoundIndex, calculateMatrixIndex;

    memset(resultMatrix, 0, sizeof(BYTE)*STATE_SIZE);
    memcpy(calculateMatrix, argMatrix, sizeof(BYTE)*STATE_SIZE);

        for(calculateMatrixIndex = 0; calculateMatrixIndex < WORD_SIZE; calculateMatrixIndex++) {
            for(calculateRoundIndex = 0; calculateRoundIndex < WORD_SIZE; calculateRoundIndex++) {
                resultMatrix[calculateMatrixIndex + calculateRoundIndex * WORD_SIZE] = 
                    getUnitMultiplication(calculateMatrix[calculateMatrixIndex][0], 
                        *(matrix+calculateRoundIndex * WORD_SIZE + 0)) ^ 
                    getUnitMultiplication(calculateMatrix[calculateMatrixIndex][1], 
                        *(matrix+calculateRoundIndex * WORD_SIZE + 1)) ^
                    getUnitMultiplication(calculateMatrix[calculateMatrixIndex][2], 
                        *(matrix+calculateRoundIndex * WORD_SIZE + 2)) ^
                    getUnitMultiplication(calculateMatrix[calculateMatrixIndex][3], 
                        *(matrix+calculateRoundIndex * WORD_SIZE + 3));
            }
        }

    for(copyIndex = 0; copyIndex < STATE_SIZE; copyIndex++)
        *(matrix+copyIndex) = resultMatrix[copyIndex];
} 
BYTE * rotWord(BYTE * wo) {
    BYTE temp = wo[0];
    wo[0] = wo[1];
    wo[1] = wo[2];
    wo[2] = wo[3];
    wo[3] = temp;
    return wo;
}
void subWord(BYTE * wo) {
    int i;
    for(i=0; i<WORD_SIZE; i++)
        *(wo+i) = sbox[wo[i]];
}
void setWord(BYTE * w, BYTE * bw, BYTE * temp) {
    int i;
    for(i=0; i<WORD_SIZE; i++) {
        *(w+i) = *(bw+i) ^ *(temp+i);
    }
}
/* 기타 필요한 함수 추가 선언 및 정의 */

/*  <키스케줄링 함수>
 *   
 *  key         키스케줄링을 수행할 16바이트 키
 *  roundKey    키스케줄링의 결과인 176바이트 라운드키가 담길 공간
 */
void expandKey(BYTE *key, BYTE *roundKey){
    /* 추가 구현 */
    BYTE temp[4];
    int index;

    memcpy(roundKey, key, sizeof(BYTE)*16);

    for (index=STATE_SIZE; index<ROUNDKEY_SIZE; index+=WORD_SIZE) {
        memcpy(temp, roundKey + index - WORD_SIZE, WORD_SIZE);
        if (index % STATE_SIZE == 0) {
            subWord(rotWord(temp));
            temp[0] = temp[0] ^ Rcon[index/STATE_SIZE];
        }
        setWord(roundKey+index, roundKey+index-STATE_SIZE, temp);
    }
}


/*  <SubBytes 함수>
 *   
 *  state   SubBytes 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    SubBytes 수행 모드
 */
 BYTE* subBytes(BYTE *state, int mode){

    /* 필요하다 생각하면 추가 선언 */
    int index;

    switch(mode){

        case ENC:
            
            /* 추가 구현 */

            for(index = 0; index < STATE_SIZE; index++)
                *(state+index) = getSBoxValue(*(state+index), mode);
            
            break;

        case DEC:

            /* 추가 구현 */

            for(index = 0; index < STATE_SIZE; index++)
                *(state+index) = getSBoxValue(*(state+index), mode);
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <ShiftRows 함수>
 *   
 *  state   ShiftRows 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    ShiftRows 수행 모드
 */
BYTE* shiftRows(BYTE *state, int mode){ 

    /* 필요하다 생각하면 추가 선언 */   
    int index, dimension, pivot;

    switch(mode){

        case ENC:
            
            /* 추가 구현 */

            for(index = 0; index < WORD_SIZE; index++)
                matrixShift(state, index);
            
            break;

        case DEC:

            /* 추가 구현 */
            for(index = 0; index < WORD_SIZE; index++) {
                matrixShift(state, index);
                if(index == 1 || index == 3) {
                    matrixShift(state, index);
                    matrixShift(state, index);
                }
            }
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <MixColumns 함수>
 *   
 *  state   MixColumns을 수행할 16바이트 state. 수행 결과는 해당 배열에 바로 반영
 *  mode    MixColumns의 수행 모드
 */
BYTE* mixColumns(BYTE *state, int mode){    

    /* 필요하다 생각하면 추가 선언 */   

    switch(mode){

        case ENC:
            
            matrixMultiplication(state, baseMatrix);
            /* 추가 구현 */
            
            break;

        case DEC:

            matrixMultiplication(state, baseInvMatrix);
            /* 추가 구현 */
            
            break;

        default:
            fprintf(stderr, "Invalid mode!\n");
            exit(1);
    }
    
    return state;
}


/*  <AddRoundKey 함수>
 *   
 *  state   AddRoundKey를 수행할 16바이트 state. 수행 결과는 해당 배열에 반영
 *  rKey    AddRoundKey를 수행할 16바이트 라운드키
 */
BYTE* addRoundKey(BYTE *state, BYTE *rKey){
    /* 추가 구현 */
    int index;
    for(index = 0; index<STATE_SIZE; index++)
        *(state+index) = *(state+index) ^ *(rKey+index);

    return state;
}


/*  <128비트 AES 암복호화 함수>
 *  
 *  mode가 ENC일 경우 평문을 암호화하고, DEC일 경우 암호문을 복호화하는 함수
 *
 *  [ENC 모드]
 *  input   평문 바이트 배열
 *  result  결과(암호문)이 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 *
 *  [DEC 모드]
 *  input   암호문 바이트 배열
 *  result  결과(평문)가 담길 바이트 배열. 호출하는 사용자가 사전에 메모리를 할당하여 파라미터로 넘어옴
 *  key     128비트 암호키 (16바이트)
 */

void test_print(BYTE * pr, int index) {
    printf("%d - ", index);
    for(index = 0; index < STATE_SIZE; index++)
        printf("%4x", *(pr+index));
    printf("\n");
}

void AES128(BYTE *input, BYTE *result, BYTE *key, int mode){
    int index, invIndex;
    BYTE roundKey[ROUNDKEY_SIZE];

    expandKey(key, roundKey);

    if(mode == ENC){
        addRoundKey(input, roundKey);
        for(index = 1; index <= 9; index++) {
            subBytes(input, mode);
            shiftRows(input, mode);
            mixColumns(input, mode);
            addRoundKey(input, roundKey + (index * STATE_SIZE));
        }
        subBytes(input, mode);
        shiftRows(input, mode);
        addRoundKey(input, roundKey + STATE_SIZE * 10);

        memcpy(result, input, sizeof(BYTE)*STATE_SIZE);

        /* 추가 작업이 필요하다 생각하면 추가 구현 */    

    }else if(mode == DEC){
        addRoundKey(input, roundKey + STATE_SIZE * 10);
        for(index = 1; index <= 9; index++) {
            subBytes(input, mode);
            shiftRows(input, mode);
            mixColumns(input, mode);
            mixColumns(roundKey + ((10 - index) * STATE_SIZE), mode);
            addRoundKey(input, roundKey + ((10 - index) * STATE_SIZE));
        }
        subBytes(input, mode);
        shiftRows(input, mode);
        addRoundKey(input, roundKey);

        memcpy(result, input, sizeof(BYTE)*STATE_SIZE);

        /* 추가 작업이 필요하다 생각하면 추가 구현 */    

    }else{
        fprintf(stderr, "Invalid mode!\n");
        exit(1);
    }
}
