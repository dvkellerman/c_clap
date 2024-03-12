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

size_t type_size(const char* type_token)
{
  // TODO: add more types
  if (strcmp(type_token, "int") == 0) {
    return 4;
  } else if(strcmp(type_token,"char*") == 0) {
    return 8;
  } else {
    return 0;
  }
}

int fill_pointer_with_value_type(char** pointer, const char* type_tkn, char* type_value)
{
    // TODO: add more types
    if (strcmp(type_tkn, "int") == 0) {
      *pointer = (char*)atoi(type_value);
      return 1;
    } else if(strcmp(type_tkn, "char*") == 0) {
      *pointer = type_value;
      return 1;
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
  const int usage_leng = strlen(argv[0]) + strlen(format) + 30;
  char *usage = malloc(usage_leng);
  usage = strncpy(usage, argv[0], strlen(argv[0]));

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

  // cli on stack
  struct CLI cli = { 0 };
  char* cli_ptr = (char*)&cli;

  // fill cli on stack from argv
  size_t offset = 0;
  for(int i = 1; i < argc; i++)
  {
    const char* type_tkn = *(types+i-1);
    char** iterator = cli_ptr+offset;
    if(!fill_pointer_with_value_type(iterator, type_tkn,argv[i]))
    {
      printf("Usage: %s\n", usage);
      return NULL;
    }
    offset += type_size(type_tkn);
  }

  // copy struct CLI from stack pointer
  const size_t cli_size = sizeof(struct CLI);
  struct CLI *c = malloc(cli_size);
  memcpy(c, cli_ptr, cli_size);
  return c;
};

int main(const int argc, char *argv[]) {
  const struct CLI *cli = parse(argc, argv);

  if (cli == NULL) return EXIT_FAILURE;

  printf("Hello, %s, age %d at location %s\n", cli->username, cli->age, cli->home);

  return EXIT_SUCCESS;
}
