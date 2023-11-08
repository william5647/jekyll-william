---
layout: post
title:  "Detecting and Exploiting Insecure Deserialization Part 1"
date:   2023-10-02 21:29:20 +0700
categories: jekyll update
usemathjax: true
tag:
  - tips
  - web application
  - insecure deserialization
image1:
  - /insecure-deserialization/img1.PNG
image2:
  - /insecure-deserialization/img2.PNG
image3:
  - /insecure-deserialization/img3.PNG
image4:
  - /insecure-deserialization/img4.PNG
image5:
  - /insecure-deserialization/img5.PNG
image6:
  - /insecure-deserialization/img6.PNG
image7:
  - /insecure-deserialization/img7.PNG
image8:
  - /insecure-deserialization/img8.PNG
image9:
  - /insecure-deserialization/img9.PNG
---

Hello readers, today we'll explore more about insecure deserialization.

Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code. 

The impact of insecure deserialization can be very severe because it provides an entry point to a massively increased attack surface. It allows an attacker to reuse existing application code in harmful ways, resulting in numerous other vulnerabilities, often remote code execution.

Even in cases where remote code execution is not possible, insecure deserialization can lead to privilege escalation, arbitrary file access, and denial-of-service attacks.

### How to identify insecure deserialization

Identifying insecure deserialization is relatively simple regardless of whether you are whitebox or blackbox testing.

During auditing, you should look at all data being passed into the website and try to identify anything that looks like serialized data. Serialized data can be identified relatively easily if you know the format that different languages use.

PHP serialization format

PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a User object with the attributes:

```
$user->name = "carlos";
$user->isLoggedIn = true;

When serialized, this object may look something like this:
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

This can be interpreted as follows:

```
O:4:"User" - An object with the 4-character class name "User"
2 - the object has 2 attributes
s:4:"name" - The key of the first attribute is the 4-character string "name"
s:6:"carlos" - The value of the first attribute is the 6-character string "carlos"
s:10:"isLoggedIn" - The key of the second attribute is the 10-character string "isLoggedIn"
b:1 - The value of the second attribute is the boolean value true
```

Java serialization format

Java uses binary serialization formats and serialized Java objects always begin with the same bytes, which are encoded as ```ac ed``` in hexadecimal and ```rO0``` in Base64.

### Modifying Serialized Objects

<figure>
<img src="{{ page.image1 }}" alt="">
<figcaption>Fig 1. Session Cookie</figcaption>
</figure>

Decode the session cookie from base64 into plaintext, modify the admin attribute into 1, and re-encode it

<figure>
<img src="{{ page.image2 }}" alt="">
<figcaption>Fig 2. New Session Cookie</figcaption>
</figure>

Use the new session cookie, to elevate our privilege into admin

<figure>
<img src="{{ page.image3 }}" alt="">
<figcaption>Fig 3. Successful Exploitation</figcaption>
</figure>


### Modifying Serialized Data Types

We've seen how you can modify attribute values in serialized objects, but it's also possible to supply unexpected data types.

PHP-based logic is particularly vulnerable to this kind of manipulation due to the behavior of its loose comparison operator (==) when comparing different data types.

This becomes even stranger when comparing a string the integer 0:
```0 == "Example string" // true```

Why? Because there is no number, that is, 0 numerals in the string. PHP treats this entire string as the integer 0. 

<figure>
<img src="{{ page.image4 }}" alt="">
<figcaption>Fig 4. Session Cookie</figcaption>
</figure>

- Update the length of the username attribute to 13.
- Change the username to administrator.
- Change the access token to the integer 0. As this is no longer a string, you also need to remove the double-quotes surrounding the value.
- Update the data type label for the access token by replacing s with i.

<figure>
<img src="{{ page.image5 }}" alt="">
<figcaption>Fig 5. New Session Cookie</figcaption>
</figure>

Use the new session cookie, to elevate our privilege into admin

<figure>
<img src="{{ page.image6 }}" alt="">
<figcaption>Fig 6. Successful Exploitation</figcaption>
</figure>

### Using Application Functionality

As well as simply checking attribute values, a website's functionality might also perform dangerous operations on data from a deserialized object. In this case, you can use insecure deserialization to pass in unexpected data and leverage the related functionality to do damage.

Notice that the serialized object has an avatar_link attribute, which contains the file path to your avatar. 

<figure>
<img src="{{ page.image7 }}" alt="">
<figcaption>Fig 7. Session Cookie</figcaption>
</figure>

Edit the serialized data to /home/carlos/morale.txt

<figure>
<img src="{{ page.image8 }}" alt="">
<figcaption>Fig 8. New Session Cookie</figcaption>
</figure>

Change the request line to POST /my-account/delete and send the request. Your account will be deleted, along with Carlos's morale.txt file. 

<figure>
<img src="{{ page.image9 }}" alt="">
<figcaption>Fig 9. Successful Exploitation</figcaption>
</figure>

So that's it for the basic of insecure deserialization, on the next blog post we will learn on how to leverage pre-built gadget chains to exploit insecure deserialization.

IB: PortSwigger
