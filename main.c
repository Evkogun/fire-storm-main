#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sniff.h"

// NON FUNCTIONAL



struct arguments {
  int verbose;
};

void print_usage(char *progname) {
  fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
  fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
}

int main(int argc, char *argv[]) {
  
  if (argc != 2) {
    printf("Error, invalid number of arguments");
    return 0;
  }

  // Parse command line arguments
  struct arguments args = {0}; // Default values

  args.verbose = atoi(argv[1]);

  if (args.verbose > 2 || args.verbose < 0){
    printf("Error, specify valid verbose argument");
    return 0;
  }

  // Print out settings
  printf("%s invoked. Settings:\n", argv[0]);
  printf("\tVerbose: %d\n", args.verbose);
  // Invoke Intrusion Detection System
  sniff(args.verbose);
  return 1;
}