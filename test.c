#include <stdio.h>
#include <stdlib.h>

int fib(int n) {
    if (n == 0) {
        return 1;
    }
    if (n == 1) {
        return 1;
    } else {
        return fib(n - 1) + fib(n - 2);
    }
}

int get_n(char* str) {
    if (str == NULL) {
        char buf[10];
        printf(">> ");
        fgets(buf, sizeof(buf), stdin);
        return atoi(buf);
    } else {
        return atoi(str);
    }
}

int main(int argc, char** argv) {
    int n = argc == 2 ? get_n(argv[1]) : get_n(NULL);

    printf("%d\n", fib(n));

    return 0;
}
