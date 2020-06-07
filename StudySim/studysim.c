#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

long allocated_count = 0;
char* stack[7];
static void handler(int signum) {
    puts("Daylight pours in through the windows. Your time is up.");
    exit(0);
}

int read_str(char* str, unsigned int length) {
  int c = 0;
  char tmp;
  while (c != length && read(0, &tmp, 1) > 0) {
    if (tmp == '\n') break;
    str[c++] = tmp;
  }
  str[length-1] = '\0'; // meh it should be ok
  return c;
}

void read_ulong(unsigned long *ptr) {
    char buf[25];
    read_str(buf, 24);
    *ptr = strtoul(buf, NULL, 10);
    return;
}

void new_worksheet(void) {
    if (allocated_count == 7) {
        puts("Your workload is too high!");
        return;
    }
    unsigned long length;
    puts("How long is your worksheet?");
    read_ulong(&length);
    if (length < 0) {
        puts("Your worksheet is too short.");
        return;
    } else if (length > 0x400) {
        puts("Your worksheet is too long;");
        return;
    }
    char * book = (char *) malloc(length + 1);
    if (book == NULL) {
        exit(1);
    }
    puts("What's the content of your worksheet?");
    read_str(book, length);
    stack[allocated_count] = book;
    allocated_count++;
    printf("You throw the worksheet '%s' on your stack of worksheets.\n", book);
    return;
}

void do_worksheets(void) {
    unsigned long count;
    puts("How many worksheets would you like to finish?");
    read_ulong(&count);
    allocated_count -= count;
    printf("You did %lu worksheets. Only %ld more to go!\n", count, allocated_count);
    return;
}

int main(void) {
    char buf[21];
    setvbuf(stdin, NULL, _IONBF, NULL);
    setvbuf(stdout, NULL, _IONBF, NULL);
    signal(0xe, handler);
    alarm(30);
    puts("Welcome to study simulator!");
    puts("Because who has free time when you must STUDY.");
    puts("Commands:");
    puts("add - Adds a worksheet onto your stack of worksheets");
    puts("do - Complete the top worksheets");
    puts("sleep - Give up and sleep");
    while (1) {
        putchar('>'); putchar(' ');
        memset(buf, 0, 21);
        read_str(buf, 20);
        if (strncmp(buf, "add", 3) == 0) {
            new_worksheet();
        } else if (strncmp(buf, "do", 2) == 0) {
            do_worksheets();
        } else if (strncmp(buf, "sleep", 5) == 0) {
            puts("Good night...");
            exit(0);
        } else {
            puts("I didn't understand that...");
        }
    }
}
