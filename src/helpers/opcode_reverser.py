#!/usr/bin/env python3
import sys
from itertools import chain

while True:
    arg = input()[::-1]
    group = 2
    result = "".join(chain.from_iterable([reversed(elem) for elem in zip(*[iter(arg)]*group)]))

    if(len(result) != len(arg)):
        print("String not with even characters?")
        #exit(1)

    print(result)

