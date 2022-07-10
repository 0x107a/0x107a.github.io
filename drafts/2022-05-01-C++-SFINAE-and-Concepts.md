---
title: "C++ SFINAE and Concepts"
categories:
  - programming
tags:
  - c++
  - c++20
---

Welcome, within this post I will be detailing two extremely important ideas within the
realm of generic programming in C++.

These techniques and features provide us with the ability to place constraints on template
parameters at compile time. With this, better error propigation and much more maintainable
code comes as a result.

## Table of Contents
- [Overload Resolution](#overload-resolution)
  * [Name Lookup](#name-lookup)
  * [Filter Candidates](#filter-candidates)
  * [Substitition](#substitition)
- [SFINAE and std::enable_if](#sfinae-and-std--enable-if)
  * [Basic Usage and Syntax of SFINAE](#basic-usage-and-syntax-of-sfinae)
- [Writing our own Type Predicates](#writing-our-own-type-predicates)
- [Expression SFINAE](#expression-sfinae)
  * [Usage of std::void_t](#usage-of-std--void-t)
  * [Detection Idiom](#detection-idiom)
  * [Implementing detect_if](#implementing-detect-if)
- [Usage of std::remove_if](#usage-of-std--remove-if)
- [Usage of std::decay](#usage-of-std--decay)
- [Additional Syntax](#additional-syntax)
- [C++20 Concepts](#c--20-concepts)
- [Basic Usage and Syntax of C++20 Concepts](#basic-usage-and-syntax-of-c--20-concepts)
- [Requires Clause](#requires-clause)
- [Requires Expression](#requires-expression)
- [Concept Constraints](#concept-constraints)
- [Concepts vs SFINAE](#concepts-vs-sfinae)
- [Practical Examples](#practical-examples)
  * [Constraints For Overloads](#constraints-for-overloads)
- [Conclusion](#conclusion)
- [Additional Resources](#additional-resources)
  * [Template Metaprogramming Resources](#template-metaprogramming-resources)
  * [SFINAE Resources](#sfinae-resources)
  * [C++20 Concepts Resources](#c--20-concepts-resources)
- [Definitions](#definitions)
  * [Type Predicate](#type-predicate)
  * [Template Subsitution and Instantiation](#template-subsitution-and-instantiation)
  * [Type Trait](#type-trait)
  * [Entity](#entity)
  * [Template Specialization](#template-specialization)
    + [Factorial](#factorial)
    + [Greatest Common Divisor](#greatest-common-divisor)


## Overload Resolution

Before we dive into SFINAE and c++20 concepts, let's first take a look at how c++ implements
automatic template argument deduction. It goes through a process to deduce the most promising
candidate from a set of signatures within the symbol table of the compiler.

This won't be too in-depth, as this is not a study on the internals of a C++ compiler; but I
will be providing a description of the general process. It is important to first understand
how templates function internally before we begin placing constraints on them.

Something to be noted is that if we are to explicitly instantiate the template, the compiler
will not go through this phase. However, automatic template paramter deduction is a very
powerful tool in the generic programmers toolkit; so this is not an option.

The process of overload resoltion is not a process done solely on c++ templates however. As
C++ supports multiple forms of static polymorphism, such as name mangling within function/method
signatures.

Here is a brief summary of the steps overload resolution takes. If you would like more information
on this topic, I have provided additional resources at the bottom of the post.

### Name Lookup

This is the first step of overload resolution; in which the compiler will simply check for valid
identifiers that may be overloaded.

If the entity is a function, then this procedure will additionally include an argument dependent
lookup. This essentially means that it will only return valid function signatures as a candidate
for overload resolution.

### Filter Candidates

If more than one potential candidate exists, then the compiler will attempt to filter the potential
signatures into a either a smaller set of signatures or a single one.

### Substitition

This is the last step, in which the compiler has either found it's valid signature to substitute,
or it has run out of potential candidates that are valid. If the signature is valid, then the
entity will be generated; else an error will be propigated about the failure to deduce and
substitute the template.

Now that we understand a bit more on the process the compiler takes to resolve and deduce the
valid signature to substitute; lets move onto SFINAE.

## SFINAE and std::enable_if

SFINAE (Substitution Failure Is Not An Error), is a means of specifying a set of constraints on
how compilers can discard template specializations in the process of overload resolution without
causing errors.

Before we get into writing code that utilized SFINAE, lets first take a deeper look at the utility
that allows us to achieve this effect. The following is a possible implementation of the
```enable_if``` template.

```cpp
template <bool B, template T=void>
struct enable_if {};

template <typename T>
struct enable_if<true, T> {
  typedef T type;
};
```

Lets now analyze this and see how this utility may help us with specifying constraints on template
parameters.

The first template serves as the primary template for our ```enable_if```. The first parameter expects
a constexpr boolean, and the second template parameter optionally expects a type; which is defaulted
to void.

The second template is a specialization, which as we can see; will be valid in the case that the
boolean passed to the template is true. If true, then the type passed within the second template
paramter will be defined within the structure as ```enable_if::type```.

As we can see, this template essentially expects a constant type constraint to evaluate to true at
the compile time instantiation of the template, else it will not be substituted. So by looking
at the implementation of ```enable_if```, we can begin to formulate an idea on how to utilize this
template to provide constraints on our template parameters.

The ```enable_if``` template will first expect a [type predicate](#type-predicate) to evaluate to either
true or false, depending on the type passed to it, and depending on the result; the template will either
be properly substituted, or the compiler will provide us with an error.

This is important, as with this technique, we can find and correctly propigate the invalid
template substitution; rather than having to dig through a massive error message. I will now
provide a demonstration of exactly this technique, as well as the repercussions of letting
our templates run wild.

### Basic Usage and Syntax of SFINAE

I've explained the notion behind SFINAE, but it's very hard to understand and visualize a
concept without practical examples; so I will provide one.

Lets take the following code as an example for our demonstration.

```cpp
#include <iostream>

template <typename T>
T add(T x, T y) {
  return x + y;
}

int main(int argc, char**argv) {
  std::cout << add(10, 10) << '\n'
  << add(5.3, 1.2) << '\n'
  << add(std::string("hello"), std::string(" world")) << std::endl;
  return 0;
}
```

Lets compile it and see the result.

```
20
6.5
hello world
```

This code in and of itself is not incorrect, nor does it fall under bad practice (besides the
horrendous style). It's an operational template, and performs its job perfectly given that we
do provide a type in which the compiler can properly substitute.

However, let's just say for example that we only want the type of the template parameter to be an
integral type. To achieve this, we can use the STL's [type traits](#type-trait) header. This header
provides us with a plethora of [type predicates](##type-predicate), as well as the utlities previously
mentioned & more; such as ```std::remove_if```, which I will cover at a later point in this blog.

Here is the reference of the [type traits](#type-trait) header:
https://en.cppreference.com/w/cpp/header/type_traits

In this case, we want to use the ```is_arithmetic``` [type predicate](##type-predicate), which simply
checks if the type passed to it is a constant integer, integer, or floating point integer. Lets 
now implement this into our example template shown above.

```cpp
#include <iostream>
#include <type_traits>

template <typename T>
typename std::enable_if<
  std::is_arithmetic<T>::value,
  T
>::type add(T x, T y) {
  return x + y;
}

int main(int argc, char**argv) {
  std::cout << add(10, 10) << '\n'
  << add(5.3, 1.2) << '\n'
  << add(std::string("hello"), std::string(" world")) << std::endl;
  return 0;
}
```

Lets attempt to compile the code and see what happens.

```cpp
example.cpp: In function ‘int main(int, char**)’:
example.cpp:16:9: error: no matching function for call to ‘add(std::string, std::string)’
   16 |   << add(std::string("hello"), std::string(" world")) << std::endl;
      |      ~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
example.cpp:9:9: note: candidate: ‘template<class T> typename std::enable_if<std::is_arithmetic<_Tp>::value, T>::type add(T, T)’
    9 | >::type add(T x, T y) {
      |         ^~~
example.cpp:9:9: note:   template argument deduction/substitution failed:
example.cpp: In substitution of ‘template<class T> typename std::enable_if<std::is_arithmetic<_Tp>::value, T>::type add(T, T) [with T = std::__cxx11::basic_string<char>]’:
example.cpp:16:9:   required from here
example.cpp:9:9: error: no type named ‘type’ in ‘struct std::enable_if<false, std::__cxx11::basic_string<char> >’
```

Now as we can see, it will produce an error as the ```enable_if``` template has prevented the
```add``` function to be deduced and substituted for the type ```std::string```.

This is one means of utilizing SFINAE for more maintainable generic code. If we have code that expected
a type that was capable of arithmetic and we had passed a ```std::string``` which is incapable of
acting within arithmetic; it would have potentially caused an error that provided little to no information
on the bug. Or even worse, a runtime error.

Remember the implementation of the enable_if template shown. It required a boolean as the first
template parameter, and a type as the second. If the ```is_arithmetic``` [type predicate](##type-predicate)
evaluates to a boolean, then we know that the overload resolution will depend on the result of the compile
time computation.

If the type T passed to ```is_arithmetic``` results in true, then enable_if will be instantiated.
If this is the case, then we can access our T type through the ::type definition within the
enable_if structure. If the predicate returns a false however, the enable_if template will
not be instantiated, and an error will be propigated by the compiler of the error.

## Writing our own Type Predicates

Using [type predicates](#type-predicate) supplied by the STL is very much recommended as its
pointless to reinvent the wheel. However, in the scenario where you find yourself in a predicament
in which you are unable to find a trait that suits your needs within the STL; you will have to get
your hands dirty.

When playing around with the demonstrations below, do not include the ```type_traits``` header, as
I have not checked for namespace conflicts.

We will be using the technique known as [template specialization](#template-specialization) to
create our type traits.

As previously said, type predicates are types that will evaluate to a boolean at compile time. The
following is a barebones type predicate which simply aims to serve as the building blocks for the
rest of our type traits.

```cpp
struct true_type {
  static constexpr bool value = true;
};
struct false_type {
  static constexpr bool value = false;
};
```

Now that we have defined the true and false types, we can now utilize these primitives during the
construction of our very own type traits.

Lets now try writing a type trait which simply checks if the type passed is of type ```int```.

```cpp
template <typename T>
struct is_integer : false_type {};

template <>
struct is_integer<int> : true_type {};
```

The first template acts as the base condition for our predicate. If the type passed through T
is not an ```int```, then the second specialized template will not be deduced, and the
```false_type``` predicate will be chosen.

Lets try using this!

```cpp
#include <iostream>

struct true_type {
  static constexpr bool value = true;
};
struct false_type {
  static constexpr bool value = false;
};

template <typename T>
struct is_integer : false_type {};

template <>
struct is_integer<int> : true_type {};

template <typename T>
bool check_if_integer(T x) {
  return is_integer<T>::value;
}

int main(int argc, char**argv) {
  std::cout << check_if_integer(12) << '\n' // true
    << check_if_integer(2.3) << std::endl; // false, floating point, did not specialize
  return 0;
}
```

This was an extremely simple demonstration of what type traits were, and how to write our
own via template specialization. I will provide more practical examples of writing our own
predicates within a later section of this post.

## Expression SFINAE



### Usage of std::void_t
### Detection Idiom

The detection idiom is a means of utilizing template constraints to determine whether a type
passed posesses a member.

### Implementing detect_if

## Usage of std::remove_if
## Usage of std::decay

## Additional Syntax

Due to the fact that SFINAE is technically a technique that can be employed, rather than a
feature within the core language; there are also multiple means of achieving the same
effect. Here, I will be demonstrating the various patterns that may be utilized to achieve
SFINAE.

All of the [type traits](#type-trait) within the STL come with predefined helper types. These
are defined as the ```_t``` and ```_v``` types which act as the ```::type``` and ```::value```
types within our type traits. This just helps us reduce the code size of our SFINAE templates.
Not that important, but fairly useful when attempting to keep our template metaprogramming
properly formatted and readable.

## C++20 Concepts

The dawn of c++20 had brought us a plethora of new fresh features to play around with. One
such feature that had been introduced is the concept.

Concepts, like SFINAE provides a means of specifying requirements on a set of template
parameters. However, it also aims to simplify the generic code that we write in C++ by
providing a simpler interface for creating and applying contraints.

## Basic Usage and Syntax of C++20 Concepts


## Requires Clause
## Requires Expression
## Concept Constraints
## Concepts vs SFINAE

Honestly, I personally feel as though its fine to utilize both. If your project supports
c++20, then it would be best practice to leverage the modern features of your compiler
and utilize concepts.

## Practical Examples

The following are some practical tricks that I have personally picked up and utilized
within my own code. They are fairly specific, but hopefully they may provide you with
more instances of where SFINAE/concepts may be utlized.

Both SFINAE and concept implementations will be included.

### Constraints For Overloads

A neat trick commonly utilized within C++ is to overload the global ostream operator
```<<<``` to our own custom classes, so they may be streamed to std::ostream.

The following is a demonstration on how to overload this global streaming operator.

```cpp
#include <iostream>

class human {
  friend std::ostream& operator<<(std::ostream& out, const human& h) {
    out << "Hello, my name is " << h.m_name
      << " and I am " << h.m_age << " years old.";
    return out;
  }
public:
  human(const std::string& name, int age)
    : m_name(name.c_str())
    , m_age(age)
  {
  }
private:
  const char* m_name;
  int m_age;
};

template <typename T>
void ostream_to_cout(const T& v) {
  std::cout << v << std::endl;
  return;
}

int main(int argc, char**argv) {
  human jerry("jerry", 21);
  ostream_to_cout(jerry);
}
```

Output of program.

```
Hello, my name is jerry and I am 21 years old.
```

Very nice, we now have an object that we can stream to ostream. But what happens if we
were to pass it a type that was not overloaded by ```ostream::operator<<```?

Lets take this program as an example.

```cpp
#include <iostream>

struct human {};

template <typename T>
void ostream_to_cout(const T& v) {
  std::cout << v << std::endl;
  return;
}

int main(int argc, char**argv) {
  human jerry;
  ostream_to_cout(jerry);
}
```

If we were to compile this, we would recieve a massive error message. It would be possible to
debug, but imagine errors such as this on the scale of a massive code base. It would cause mass
hysteria.

Feel free to compile the code provided and look at the error message provided by the compiler.
I wont be showing the error message here as it would bloat up the post.

Now lets write our own [type predicate](##type-predicate) to check if a type has been overloaded
for the ```ostream::operator<<```.

```cpp
template <typename S, typename T, typename=void>
struct is_ostreamable : std::false_type {};

template <typename S, typename T>
struct is_ostreamble<S, T,
  typename std::void_t<
    decltype(
      std::declval<S>() << std::declval<T>()
    )>
> : std::true_type {};
```

This [type predicate](#type-predicate) will use ```std::declval```, which we have previously covered within the
[expression SFINAE](#expression-sfinae) section of this post.

Now lets use this within our program and take a gander at the error message.

```
example.cpp: In function ‘int main(int, char**)’:
example.cpp:27:18: error: no matching function for call to ‘ostream_to_cout(human&)’
   27 |   ostream_to_cout(jerry);
      |   ~~~~~~~~~~~~~~~^~~~~~~
example.cpp:20:8: note: candidate: ‘template<class T, class> void ostream_to_cout(const T&)’
   20 | > void ostream_to_cout(const T& v) {
      |        ^~~~~~~~~~~~~~~
example.cpp:20:8: note:   template argument deduction/substitution failed:
In file included from /usr/include/c++/12.1.0/bits/move.h:57,
                 from /usr/include/c++/12.1.0/bits/exception_ptr.h:43,
                 from /usr/include/c++/12.1.0/exception:168,
                 from /usr/include/c++/12.1.0/ios:39,
                 from /usr/include/c++/12.1.0/ostream:38,
                 from /usr/include/c++/12.1.0/iostream:39,
                 from example.cpp:1:
/usr/include/c++/12.1.0/type_traits: In substitution of ‘template<bool _Cond, class _Tp> using enable_if_t = typename std::enable_if::type [with bool _Cond = false; _Tp = void]’:
example.cpp:18:3:   required from here
/usr/include/c++/12.1.0/type_traits:2614:11: error: no type named ‘type’ in ‘struct std::enable_if<false, void>’
 2614 |     using enable_if_t = typename enable_if<_Cond, _Tp>::type;
      |           ^~~~~~~~~~~
```

Much more readable and concise isn't it? Now that we have employed SFINAE, the error message will not
exponentially spiral out of control.

All versions of C++11 and above already implement SFINAE on std::ostream, but this is still a very
practical technique that may be employed within a large variety of scenarios.

## Conclusion

That's all for me today. Hopefully by the end of this post, you understand the general idea
behind SFINAE & concepts, as well as the practicality of such a technique/feature within
generic programming in C++.

If you are having trouble with some topics, I have provided additional resources, as well as
references below.

If there has been an incorrect statement or error on my part within this post, please inform
me via either one of my contacts shown on the left. I will try to respond as soon as possible.

Thanks for reading and have a great day!

## Additional Resources
### Template Metaprogramming Resources
### SFINAE Resources
### C++20 Concepts Resources

## Definitions

Definitions of various opaque terms utilized within this post.

### Type Predicate

A type predicate is exactly as the term ```predicate``` implies, which is simply an entity that
evaluates to a boolean. In the case of a type predicate, it will take a type, check for some
condition, and evaluate to a boolean.

### Template Subsitution and Instantiation

The term template substitution refers to the process that the compiler takes to create a new
definition of a function, class, or class member. The term intantiation refers to the idea,
and I will be using either interchangeably throughout the course of this post.

### Type Trait

A type trait is a technique within generic programming, which allows us to write
[type predicates](#type-predicate) which aim to deduce traits about types. These type traits
allow us to define and place constraints on template paramters, although c++20 provided us
with another means of defining these through the ```requires``` expression.

See the [c++20 concepts](#c++20-concepts) section for more on the ```requires``` expression.

### Entity

An entity within a C++ program is anything that is generalltangible to the runtime of the
C++ compiler. An example of something that is not an entity is a preprocessor macro, as
they perform modifications to the code before the compiler begins.

Here is a more complete list of everything that is considered an entity within c++:
https://en.cppreference.com/w/cpp/language/basic_concepts

### Template Specialization

Template specialization is a technique which allows the programmer to define custom the
contents of the template for a given set of predefined template arguments. Multiple examples
of how template specialization may be used are shown below.

#### Factorial

We can calculate the factorial of an integer at compile time using template specialization
as the base case for the recursive loop.

```cpp
template <int N>
struct factorial {
  static constexpr int value = N * factorial<N-1>::value;
};

template <>
struct factorial<0> {
  static constexpr int value = 1;
};
```

#### Greatest Common Divisor

The same can be done for the Euclidean GCD algorithm. This algorithm demonstrates how
partial specialization works.

```cpp
template <int X, int Y>
struct gcd {
  static constexpr int value = gcd<Y, X % Y>::value;
};

template <int X>
struct gcd<X, 0> {
  static constexpr int value = X;
};
```

Although these examples seem a bit silly at first glance, there are potentially some very
niche applications for compile-time data generation/modification. Anyways, I think its a
good way to teach template specialization and template metaprogramming in general.

See the [Writing our own Type Predicates](#writing-our-own-type-predicates) section of
this post for more information on the practical usage of this technique.

Additional reference for template specialization:
https://en.cppreference.com/w/cpp/language/template_specialization
