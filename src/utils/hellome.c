#include <stdio.h>

int dummy(int a, int b) {
    // Just return the sum
    return a + b;
}

int main(void) {
    int result = dummy(3, 5);
    printf("Result: %d\n", result);
    return 0;
}