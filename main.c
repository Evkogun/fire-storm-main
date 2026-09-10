#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sniff.h"


struct arguments {
  int flag;
  int verbose;
};

void print_usage(char *progname) {
  fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
  fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
}

int main(int argc, char *argv[]) {
  
  if (argc != 2 && argc != 3) {
    printf("Error, invalid number of arguments");
    return 1;
  }

  // Parse command line arguments
  struct arguments args = {0}; // Default values

  args.flag = atoi(argv[1]);
  if (argc > 2) {
    if (strcmp(argv[2], "v") != 0) {
        printf("Error, specify valid verbose argument\n");
        return 1;
    }
    args.verbose = 1;
  } else {
    args.verbose = 0;
  }

  if (args.flag > 2 || args.flag < 0){
    printf("Error, specify valid verbose argument");
    return 1;
  }

  // Print out settings
  printf("%s invoked. Settings:\n", argv[0]);
  printf("\tFlag: %d\n", args.flag);
  printf("\tVerbose: %d\n", args.verbose);
  // Invoke Intrusion Detection System
  sniff(args.flag, args.verbose);
  return 0;
}