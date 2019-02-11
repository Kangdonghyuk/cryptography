/*
 * @file    rsa.c
 * @author  작성자 이름 / 학번
 * @date    작성 일자
 * @brief   mini RSA implementation code
 * @details 세부 설명
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "miniRSA.h"

uint p, q, e, d, n;

#define RND_AVG RND_MAX - RND_MIN

#define true TRUE
#define false FALSE

#define GETQUOTIENT(num) (num >> 32) //quotient
#define GETREMAINDER(num) (num & 0xffffffff) //remainder
#define ISODD(num) ((num & 0x01) == 0x01)

/*
 * @brief     bit 자리수를 알려주는 함수
 * @param     uint num     : 알고싶은 숫자
 * @return    uint positional : num의 비트 수
 */
byte getPositionalNumber(uint num) {
    byte positional = 1;

    while(num >= 1) {
        num = num >> 1;
        positional += 1;
    }

    return positional;
}

/*
 * @brief     나누기 함수
 * @param     uint dividend    : 피제수
 * @param     uint divisor     : 제수
 * @return    unsigned long long result : 피제수/제수 64bit 변수로 앞 32비트는 몫, 뒤 32비트는 나머지로 한다.
 * @todo      값을 알고싶으면 Define된 GETQUOTIENT, GETREMAINDER을 이용한다.
 */
unsigned long long bitDivide(uint dividend, uint divisor) {
    unsigned long long result = 0;
    uint quotient = 0;
    byte positional = 0;

    while(dividend >= divisor) {
        positional = getPositionalNumber(dividend) - getPositionalNumber(divisor);
        if(dividend >= divisor << positional) {
            dividend = dividend - (divisor << positional);
            quotient += (1 << positional);
        }
        else {
            dividend = dividend - (divisor << (positional - 1));
            quotient += (1 << (positional-1));
        }
    }

    result = quotient;
    result = (result << 32) + dividend;

    return result;
}

/*
 * @brief     모듈러 덧셈 연산을 하는 함수.
 * @param     uint a     : 피연산자1.
 * @param     uint b     : 피연산자2.
 * @param     byte op    : +, - 연산자.
 * @param     uint n      : 모듈러 값.
 * @return    uint result : 피연산자의 덧셈에 대한 모듈러 연산 값. (a op b) mod n
 * @todo      모듈러 값과 오버플로우 상황을 고려하여 작성한다.
 */
uint ModAdd(uint a, uint b, byte op, uint n) {
    uint result = 0;
    uint first, second;

    if((a + b) < a || (a + b) < b) {
        first = (a >= b) ? a : b;
        second = (a < b) ? a : b;
        result = first - (n - second);
    }
    else
        result = GETREMAINDER(bitDivide(a + b, n));

    return result;
}

/*
 * @brief      모듈러 곱셈 연산을 하는 함수.
 * @param      uint x       : 피연산자1.
 * @param      uint y       : 피연산자2.
 * @param      uint n       : 모듈러 값.
 * @return     uint result  : 피연산자의 곱셈에 대한 모듈러 연산 값. (a x b) mod n
 * @todo       모듈러 값과 오버플로우 상황을 고려하여 작성한다.
 */
uint ModMul(uint x, uint y, uint n) {
    uint result = 0;
    uint temp = x;

    while(y > 0) {     
        if(ISODD(y))
            result = ModAdd(result,temp,'+',n); 
        temp = ModAdd(temp,temp,'+',n);
        y = y >> 1; 
    }
    
    return result;
}

/*
 * @brief      모듈러 거듭제곱 연산을 하는 함수.
 * @param      uint base   : 피연산자1.
 * @param      uint exp    : 피연산자2.
 * @param      uint n      : 모듈러 값.
 * @return     uint result : 피연산자의 연산에 대한 모듈러 연산 값. (base ^ exp) mod n
 * @todo       모듈러 값과 오버플로우 상황을 고려하여 작성한다.
               'square and multiply' 알고리즘을 사용하여 작성한다.
 */
uint ModPow(uint base, uint exp, uint n) {
    uint result = 1;

    if((base < 1) || (n < 1))
        return 0;

    while(exp > 0) {
        if(ISODD(exp))
            result = ModMul(result, base, n);
        base = ModMul(base, base, n);
        exp = exp >> 1;
    }

    return result;
}

/*
 * @brief      입력된 수가 소수인지 입력된 횟수만큼 반복하여 검증하는 함수.
 * @param      uint testNum   : 임의 생성된 홀수.
 * @param      uint repeat    : 판단함수의 반복횟수.
 * @return     uint result    : 판단 결과에 따른 TRUE, FALSE 값.
 * @todo       Miller-Rabin 소수 판별법과 같은 확률적인 방법을 사용하여,
               이론적으로 4N(99.99%) 이상 되는 값을 선택하도록 한다. 
 */
bool IsPrime(uint testNum, uint repeat) {
    uint randNum;

    while(repeat > 0) {
        do {
            randNum = GETREMAINDER(bitDivide(WELLRNG512a()*1000000,RND_AVG)) + RND_MIN;
        }while(gcd(randNum, testNum) != 1);

        if(ModPow(randNum, testNum-1, testNum) != 1)
            return false;
        repeat--;
    }
    return true;
}

/*
 * @brief       모듈러 역 값을 계산하는 함수.
 * @param       uint a      : 피연산자1.
 * @param       uint m      : 모듈러 값.
 * @return      uint result : 피연산자의 모듈러 역수 값.
 * @todo        확장 유클리드 알고리즘을 사용하여 작성하도록 한다.
 */
uint ModInv(uint a, uint m) {
    uint result = 0;
    uint quotient, remainder;
    uint sNow = 0, xBefore=1, xAfter=0;
    uint tNow = 0, yBefore=0, yAfter=1;

    while(m > 0)
    {
        quotient = GETQUOTIENT(bitDivide(a,m));
        remainder = GETREMAINDER(bitDivide(a,m));

        sNow = xBefore - (quotient * xAfter);
        tNow = yBefore - (quotient * yAfter);

        xBefore = xAfter; 
        xAfter = sNow;
        yBefore = yAfter;
        yAfter = tNow;

        a = m;
        m = remainder;
    }
    if(a == 1) 
        result = yBefore;

    return result;
}

/*
 * @brief     RSA 키를 생성하는 함수.
 * @param     uint *p   : 소수 p.
 * @param     uint *q   : 소수 q.
 * @param     uint *e   : 공개키 값.
 * @param     uint *d   : 개인키 값.
 * @param     uint *n   : 모듈러 n 값.
 * @return    void
 * @todo      과제 안내 문서의 제한사항을 참고하여 작성한다.
 */
void miniRSAKeygen(uint *p, uint *q, uint *e, uint *d, uint *n) {
    uint wisoo;

    /*do {
        *p = GETREMAINDER(bitDivide(WELLRNG512a() * 10000000000000000, RND_AVG) + RND_MIN);
    }while(!IsPrime(*p, 5));
    do {
        *q = GETREMAINDER(bitDivide(WELLRNG512a() * 10000000000000000, RND_AVG) + RND_MIN);
    }while(!IsPrime(*q, 5));*/

    *p = 3;
    *q = 7;

    *n = *p * *q;
    wisoo = (*p - 1) * (*q - 1);

    do {
        *e = 5;
        //*e = WELLRNG512a() * 10000000000000000;
        *d=ModInv(wisoo,*e);
    }while(gcd(*e, wisoo) != 1 || wisoo <= *e || ModMul(*e, *d, wisoo) != 1);
}

/*
 * @brief     RSA 암복호화를 진행하는 함수.
 * @param     uint data   : 키 값.
 * @param     uint key    : 키 값.
 * @param     uint n      : 모듈러 n 값.
 * @return    uint result : 암복호화에 결과값
 * @todo      과제 안내 문서의 제한사항을 참고하여 작성한다.
 */
uint miniRSA(uint data, uint key, uint n) {
    uint result;

    printf("input data : %u\n", data);
    result = ModPow(data, key, n);
    printf("output data : %u\n", result);

    return result;
}

uint gcd(uint a, uint b) {
    uint prev_a;

    while(b != 0) {
        printf("GCD(%u, %u)\n", a, b);
        prev_a = a;
        a = b;
        while(prev_a >= b) prev_a -= b;
        b = prev_a;
    }
    printf("GCD(%u, %u)\n\n", a, b);
    return a;
}

int main(int argc, char* argv[]) {
    byte plain_text[4] = {0x12, 0x34, 0x56, 0x78};
    uint plain_data, encrpyted_data, decrpyted_data;
    uint seed = time(NULL);

    memcpy(&plain_data, plain_text, 4);

    // 난수 생성기 시드값 설정
    seed = time(NULL);
    InitWELLRNG512a(&seed);
    printf("%f\n", WELLRNG512a());
    // RSA 키 생성
    miniRSAKeygen(&p, &q, &e, &d, &n);
    printf("0. Key generation is Success!\n ");
    printf("p : %u\n q : %u\n e : %u\n d : %u\n N : %u\n\n", p, q, e, d, n);

    // RSA 암호화 테스트
    encrpyted_data = miniRSA(plain_data, e, n);
    printf("1. plain text : %u\n", plain_data);    
    printf("2. encrypted plain text : %u\n\n", encrpyted_data);

    // RSA 복호화 테스트
    decrpyted_data = miniRSA(encrpyted_data, d, n);
    printf("3. cipher text : %u\n", encrpyted_data);
    printf("4. Decrypted plain text : %u\n\n", decrpyted_data);

    // 결과 출력
    printf("RSA Decryption: %s\n", (decrpyted_data == plain_data) ? "SUCCESS!" : "FAILURE!");

    return 0;
}