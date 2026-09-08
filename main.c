#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "sniff.h"

// NON FUNCTIONAL


// Command line options
#define OPTSTRING "vi:"
static struct option long_opts[] = {
  {"verbose",   optional_argument, NULL, 'v'}
};

struct arguments {
  int verbose;
};

void print_usage(char *progname) {
  fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
  fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
  fprintf(stderr, "\t-v\t\tEnable verbose mode. Useful for Debugging\n");
}

int main(int argc, char *argv[]) {
  // Parse command line arguments
  struct arguments args = {0}; // Default values
  int optc;

  while ((optc = getopt_long(argc, argv, OPTSTRING, long_opts, NULL)) != EOF) {
    switch (optc) {
      case 'v':
        args.verbose = 1;
        break;
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  if (args.verbose != 0 && args.verbose != 1){
    printf("Error, specify valid verbose argument");
    return 0;
  }

  // Print out settings
  printf("%s invoked. Settings:\n", argv[0]);
  printf("\tVerbose: %d\n", args.verbose);
  // Invoke Intrusion Detection System
  sniff(args.verbose);
  return 0;
}