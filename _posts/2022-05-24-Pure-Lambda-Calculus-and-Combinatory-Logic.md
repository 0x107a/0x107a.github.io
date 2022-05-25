---
title: "Pure Lambda Calculus and Combinatory Logic"
date: 2022-05-24
categories:
  - theory
tags:
  - math
  - functional
---

Lambda Calculus is a formal system which exists within the realm of mathematical logic.
The Lambda Calculus was created by Alonzo Church, in 1930, as a means of studying the
underlying primitives of mathematical logic.

Within this post, I will primarily be focusing on teaching the core foundations behind
the pure (untyped) Lambda Calculus, whilst also attempting to convey the concept of
combinators. There will be future posts detailing the various type systems in which
this logic system also applies to.

## Description and History

Lambda Calculus is a system of logic can be utilized to express computation, equivalent 
to that of a turing machine. The Church-Turing thesis states that, "A function on the 
natural numbers can be calculated by an effective method if and only if it is computable
by a Turing machine". This definition of equivalence simply implies the fact that the
Lambda Calculus is Turing complete; which is a prerequisite for all effective programming
languages.

In fact, the Lambda Calculus was one of the earliest conceptions of what is now known as
a programming language, and has served as the foundation of functional programming
for decades.

The primary goal behind the conception of the λ symbol was to provide a systematic
means of providing distinct names to functions. Hence, came about the concept of
anonymous functions.

Anonymous functions, as the name implies, are functions which do not have a static
identifier assigned to them. Instead, they are either assigned to a variable, or
passed to another function as a parameter; which paves the way to higher order
functions within our system of logic.

## Basic Syntax of Lambda Calculus

Now that we understand what a lambda function is, lets begin with the syntax of the
Lambda Calculus.

```
expression -> name | function | application
function -> λ name . expression
application -> ( expression expression )
```

As we can see, the syntax for pure Lambda Calculus is extremely simplistic, which
makes it's Turing completeness all the more elegant. 

A simple lambda expression may be written in the following format:

```
f = λx.(x + 1)
```

This lambda expression is semantically equivalent to the algebraic function: f(x) x + 1.
As we can see from the BNF syntax provided above, the shown example matches to the
function nonterminal. This is the basic syntax for declaring a lambda expression.

For our last example, let's attempt to convert a simple algebraic function into a lambda
expression. The algebraic function we want to convert is as follows: f(x) x * x.

Answer:
```
f = λx.(x * x)
```

The bounded variable does not have to be x, nor does it have to be a single character
at all. Simply by convention and readability, I have chosen to exclusively use a
set of single character lowercase letters listed within the description section of this
post.

I will delve deeper into the syntax and evaluation of these expressions further into
the post, as there is some prerequisite information we must cover before we progress.

## Free and Bound Variables

The concept of free and bound variables has to do with the scope in which each variable
has been bound to. Binding a variable is the process of assigning an identifier to a
variable, which acts as a placeholder for the argument. A variable is free if it is
not bound within the abstraction in which it is used.

Here is an example of a nested lambda expression which demonstrates how we can utilize
free variables.

```
f = λx.(λy.(x - y))
```

As we can see, the variable x is free because it has been bound within a parent
abstraction. This allows the inner function to access the variable x & properly
perform it's operation.

## α Conversion and Equivalence



## Currying

Currying is the technique of converting a function that takes multiple arguments into a
valid sequence of functions that each take a single argument. This is important, as
an abstraction within Lambda Calculus must contain at most one argument/bound variable.

Lets take this incorrect abstraction and convert it into a valid sequence of terms.

Invalid:
```
f = (λxy.(x + y))
```

Valid:
```
f = (λx.(λy.(x + y)))
```

We have curried the second parameter by simply passing it to our higher function as a
parameter. The inner term will then add the bound y with the free x, which will return
in the correct result.

Here are some more examples of currying invalid abstractions.

```
Invalid: 
Valid: 

Invalid: 
Valid: 

Invalid: 
Valid: 

Invalid: 
Valid: 

Invalid: 
Valid: 
```

## β Equivalence
## β Reduction
### Normal Order Evaluation
### Applicative Order Evaluation
### Lazy Evaluation
### Eager Evaluation
## The Church-Rosser Theorem
## Church Numerals
## η Reduction
## Combinatory Logic

Combinatory Logic is a notation which aims to simplify and abstract Lambda Calculus. It
provides an abstract system in which we are provided predefined combinators, which we
can utilize when constructing a new system. It achieves this by removing the need for
bound variables within the expression, and replacing them with combinators.

Some standard combinators are I, K, S, B, and C, in which I will explain in more detail
later.

## History of Combinatory Logic

The concept of combinators was introduced by Moses Schönfinkel and Haskell Curry originally
within 1920. This idea later evolved through the years to eventually form into a whole
other branch of mathematics, albeit closely related to the Lambda Calculus & other systems
of logic.

## Introduction to Combinatory Logic
combinatory terms
reduction in combinatory logic
SKI

## Reducability and Provability

## Additional Combinatory Systems
## Fixed Point Combinators and Recursion
## Bohm's Theorem
## Quasi Leftmost Reduction Theorem
## Primitive and Total Recursive Functions
## Abstract Numerals
## The Undecidability Theorem
## Practical Combinatory Logic
random fun combinators
xor combinator
functional programming & it's relation to lambda calc & combinatory logic
plug our lambda calculus interpreter to people :)

## Last Notes

This concludes my introduction to Lambda Calculus and Combinatory Logic. If any information
presented within this post is incorrect or vaguely explained, please inform me via my
contact information listed on my [https://0x107a.github.io/about](about) page.

The next part of this post will delve much deeper into typed Lambda Calculus, as well as
the massive plethora of type systems that exist. It will focus primarily on the concept
of Type Theory. Stay tuned for that :)

## Additional Resources

```
https://en.wikipedia.org/wiki/Lambda_calculus
https://crypto.stanford.edu/~blynn/lambda/
https://plato.stanford.edu/entries/lambda-calculus/
https://plato.stanford.edu/entries/logic-combinatory/
https://en.wikipedia.org/wiki/SKI_combinator_calculus
https://plato.stanford.edu/entries/church-turing/
https://en.wikipedia.org/wiki/Church%E2%80%93Turing_thesis
https://en.wikipedia.org/wiki/Combinatory_logic
https://okmij.org/ftp/tagless-final/ski.pdf
https://en.wikipedia.org/wiki/Church_encoding
```

## Definitions

This section should somewhat act as a reference for the various terms utilized within
this post, as is becomes very messy if I were sprinkle keyword definitions all over
the place.

##### λ-term

All variables and atomic constants are known as λ-terms (atoms).

##### Letter Notation

Capital letters such as M, N, P and Q denote arbitrary λ-terms utilized for
demonstration purposes.

Lowercase letters such as x, y, z, u and v will be used to denote variables within
the examples provided.

##### Application

Assuming M and N are λ-terms, then (M N) is an λ-term called an application.

##### Abstraction

If M is any λ-term and x is any variable, then (λx. M) is an λ-term known as an
abstraction. Another way to phrase this is that it's an unevaluated abstraction.

##### Constant Abstractions

A constant abstraction is simply an abstraction which returns a constant value
or free variable.

Here is a simple example:
```
(λx.y)(N) = y
```

Here I have defined an abstraction with a bound variable of x, but we return a free
variable of y. Since the value of this abstraction will always return the constant/free
value of y, it is a constant abstraction.

##### Confluence

The term confluence refers to, if a term can be reduced to two different terms, then
these two terms can further reduce to another single term. 

The Church-Rosser theorem states that the reduction rules of Lambda Calculus are confluent.
A result of this theorem, is that a term within Lambda Calculus has at most one normal form.