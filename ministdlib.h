#include <stdint.h>
#pragma once

void* _memset(void * dst, int s, size_t count);
size_t _strlen(const char *s);
int _strcmp (const char *s1, const char *s2);
void * _memcpy (void *dst, const void *src, size_t n);
void _puts(char *buf);
int _strncmp (const char *s1, const char *s2, size_t sz);