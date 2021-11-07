#pragma once
#include "DataContainer.h"

#define RANDOM_SUCCESS 0
#define RANDOM_ERROR -1


class Random
{
public:
	Random();
	~Random();

	static int GenRandom(DataContainer *pobjData, int iSize);
};

