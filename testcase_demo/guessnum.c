#include <stdlib.h>
#include <stdio.h>

int target(int input)
{
    if (input < 0) {
        if (input < -18) {
            return 3;
        } else if (input == -6) {
            return 2;
        } else if (input == -3) {
            return 0;
        } else if (input == -1) {
            return 1;
        }
    } else {
        if (input < 10) {
            if (input == 3) {
                return 5;
            }
            if (input == 4) {
                return 6;
            }
        } else {
            if (input == 12) {
                return 7;
            } else if (input == 15) {
                return 8;
            } else {
                return 4;
            }
        }
    }
    return -1;
}

int main(int argc, char** argv)
{
    int res;

    if (argc <= 1) {
        return -1;
    }

    int input = strtol(argv[1], NULL, 0);

    res = target(input);
    if (!res) {
        printf("Win!");
    }

    return res;
}
