#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLI(params)                                                            \
struct CLI {                                                                   \
  params                                                                       \
} __attribute__((packed));                                                     \
                                                                               \
char *ltrim(char *input) {                                                     \
    while (isspace(*input))                                                    \
      input++;                                                                 \
    return input;                                                              \
}                                                                              \
                                                                               \
char *rtrim(char *input) {                                                     \
  char *back;                                                                  \
  int len = strlen(input);                                                     \
                                                                               \
  if (len == 0) {                                                              \
    return input;                                                              \
  }                                                                            \
                                                                               \
  back = input + len;                                                          \
                                                                               \
  while (isspace(*--back));                                                    \
  *(back + 1) = '\0';                                                          \
  return input;                                                                \
}                                                                              \
                                                                               \
char *trim(char *input) { return rtrim(ltrim(input)); }                        \

static const char* __builtin_stack_address()
{
  char* res = NULL;
  asm("mov %%rsp, %0":"=a"(res));
  return res;
}

size_t size_of(const char* type_token)
{
  if (strcmp(type_token, "int") == 0) {
    return 4;
  } else if(strcmp(type_token,"char*") == 0) {
    return 8;
  } else {
    return 0;
  }
}

CLI(char *username; int age; char *home;)

#define params char* username; int age; char* home;
#define str(a) _str(a)
#define _str(a) ""#a""
#define DEBUG_PRINT 0

// TODO: move inside macro
struct CLI* parse(const int argc, char **argv) {
  const char *format = str(params), *name_subtoken = "", *type_token = NULL;
  char *fcopy = strdup(format), *token, *subtoken;

  // Usage string, used to display names of arguments
  int nameLen = strlen(argv[0]);
  for(int i = 1; i < argc; i++)
  {
    nameLen += strlen(argv[1]) + 15;
  }
  char *usage = malloc(nameLen * sizeof(char));
  usage = strncpy(usage, argv[0], nameLen);

  // types
  char** types = malloc(sizeof(char**) * argc-1);
  uint8_t cli_argc = 0;
  while ((token = strsep(&fcopy, ";"))) {
    if (strlen(token) > 0) {
      char *trimmed = trim(token);
#if  DEBUG_PRINT
      printf("%s\n", trimmed);
#endif

      while ((subtoken = strsep(&trimmed, " "))) {
        if (type_token == NULL)
        {
          type_token = subtoken;
        }
        name_subtoken = subtoken;
#if DEBUG_PRINT
        printf("%s\n", subtoken);
#endif
      }
      // store name token
      usage = strcat(usage, " ");
      usage = strcat(usage, "<");
      usage = strcat(usage, name_subtoken);
      usage = strcat(usage, ":");
      usage = strcat(usage, type_token);
      usage = strcat(usage, ">");
      // store type token
      const size_t tkn_len = strlen(type_token);
      *(types+cli_argc) = malloc(tkn_len + 1);
      strncpy(*(types+cli_argc), type_token, tkn_len);
      type_token = NULL;
      // count argument
      cli_argc++;
    }
  }

  if (cli_argc != argc - 1) {
    printf("Usage: %s\n", usage);
    return NULL;
  }

  // declare params
  const size_t cli_size = sizeof(struct CLI);
  size_t offset = 0;

  // get stack pointer

  const char* type_tkn = NULL;
  const char **start = (char**)(__builtin_stack_address() + cli_size);
  params;


  // fill params from argv
  for(int i = 1; i < argc; i++)
  {
    type_tkn = *(types+i-1);
    if (strcmp(type_tkn, "int") == 0) {
      *(start+offset) = (char*)atoi(argv[i]);
    } else if(strcmp(type_tkn, "char*") == 0) {
      *(start+offset) = argv[i];
    } else {
      printf("Usage %s\n", usage);
    }
    offset += size_of(type_tkn);
  }

  // copy struct CLI from stack pointer
  struct CLI *c = malloc(cli_size);
  memcpy(c, start, cli_size);
  return c;
};

int main(const int argc, char *argv[]) {
  const struct CLI *cli = parse(argc, argv);

  if (cli == NULL) return EXIT_FAILURE;

  printf("Hello, %s \n", cli->username);

  return EXIT_SUCCESS;
}
