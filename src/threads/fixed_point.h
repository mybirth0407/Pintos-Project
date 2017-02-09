#ifndef THREAD_FIXED_POINT_H
#define THREAD_FIXED_POINT_H

#define F (1 << 14) //fixed point 1
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

// x and y denote fixed_point numbers in 17.14 format
// n is an integer

int int_to_fp (int n);          /* integer 를 fixed point 로 전환 */
int fp_to_int_round (int x);    /* FP 를 int 로 전환 (반올림) */
int fp_to_int (int x);          /* FP 를 int 로 전환 (버림) */
int add_fp (int x, int y);      /* FP 의 덧셈 */
int add_mixed (int x, int n);   /* FP 와 int 의 덧셈 */
int sub_fp (int x, int y);      /* FP 의 뺄셈 (x - y) */
int sub_mixed (int x, int n);   /* FP 와 int 의 뺄셈 (x - n) */
int mult_fp (int x, int y);     /* FP 의 곱셈 */
int mult_mixed (int x, int y);  /* FP 와 int 의 곱셈 */
int div_fp (int x, int y);      /* FP 의 나눗셈 (x / y) */
int div_mixed (int x, int n);   /* FP 와 int 나눗셈 (x / n)  */

int
int_to_fp (int n)
{
  return n * F;
}

int
fp_to_int_round (int x)
{
  return x / F;
}

int
fp_to_int (int x)
{
  return x >= 0 ? (x + F / 2) / F: (x - F / 2) / F;
}

int
add_fp (int x, int y)
{
  return x + y;
}

int
add_mixed (int x, int n)
{
  return x + n * F;
}

int
sub_fp (int x, int y)
{
  return x - y;
}

int
sub_mixed (int x, int n)
{
  return x - n * F;
}

int
mult_fp (int x, int y)
{
  return ((int64_t) x * y) / F;
}

int
mult_mixed (int x, int n)
{
  return x * n;
}

int
div_fp (int x, int y)
{
  return ((int64_t) x * F) / y;
}

int
div_mixed (int x, int n)
{
  return x / n;
}

#endif /* threads/fixed_point.h */