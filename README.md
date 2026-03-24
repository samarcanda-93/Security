# Expression Evaluator

**Author:** G. Accorto

TODO: Update README

IMPORTANT: Unless I misunderstood the problem somehow, tests 5 and 6 in the pdf
are wrong. I replaced them in the main with what I believe is the correct answer.

The program takes a string representing a logic expression with a
number of implicit variables and elaborates its truthiness based on the values contained in a map.

### Assumptions

- The expression validation is limited. It only detects mismatching brackets and
  malformed operations.
- The map that specify the values of variables is complete
- Supported operations are : `!`, `&&`, `||`, `==`, `!=`, `>`, `<`, `>=`, `<=`
- `!`, `&&`, `||` are strictly bool operations (no "0 || true")
- `>`, `<`, `>=`, `<=` are strictly numeric operations
- `==`, `!=` require either boolean or numeric operands (no "1 == true")
- Supported operands are boolean (`true`, `false`), numeric values,
  round brackets, `(`, `)`, and variables.
- The tokenizer needs well-spaced expressions and well-defined token. For
  example, `true==false` or `v0 > 12abc` break the tokenizer.

## Implementation

The algorithm relies on two steps:

1. Preprocessing: replace the map values into the expression, generate and
   classify a list of tokens.
2. Evaluate the expression.

During variable replacement, keys are processed by length descending to avoid
partial replacements (`v10 > 42 && v1 == 1`, `m = {v1:5, v10:42}`).

The idea is to represent a token as a struct Token, storing
the string value and the logical type. This enabled simpler switch-case logic
instead of many if/else blocks. It also simplified the distinction between unary
and binary operations, the evaluation logic (operation precedence, operation
requirements).

Alternative approach I considered: An abstract class Token, with two subclasses
Operation (And, Or, Greater) and Operand(Numeric, Bool). This would have
possibly led to a solution based on operator overloading and polymorphism.
Probably more scalable, more elegant, but way more abstract.

I considered two approaches for the evaluation in linear time:

1. Recursive
2. Dijkstra's algorithm (https://en.wikipedia.org/wiki/Shunting_yard_algorithm)
   Both approaches have O(n) space complexity, where n is the size of the input
   expression.

A recursive approach would have maybe been better for managing precedence of operators,
but it is more mind-bending and risks stack overflow. Dijkstra's algorithm is
iterative, so easier to debug. I used the latter.

## Testing

A home-made test suite is included, including both unit tests and the e2e tests
included in [ExpressionEvaluator.pdf](ExpressionEvaluator.pdf)

## Requirements

- C++20 compiler and standard library.
- CMake 3.28 or newer

## Build and Run

### Build and run the program

```bash
cmake -S . -B build
cmake --build build
./build/ExpressionEvaluator
```

### Build and run tests

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build
./build/tests
```
