---
layout: post
title:  "Detecting and Exploiting Insecure Deserialization Part 2"
date:   2023-10-09 21:29:20 +0700
categories: jekyll update
usemathjax: true
tag:
  - tips
  - web application
  - insecure deserialization
image1:
  - /insecure-deserialization-2/img1.PNG
image2:
  - /insecure-deserialization-2/img2.PNG
image3:
  - /insecure-deserialization-2/img3.PNG
image4:
  - /insecure-deserialization-2/img4.PNG
image5:
  - /insecure-deserialization-2/img5.PNG
image6:
  - /insecure-deserialization-2/img6.PNG
image7:
  - /insecure-deserialization-2/img7.PNG
image8:
  - /insecure-deserialization-2/img8.PNG
image9:
  - /insecure-deserialization-2/img9.PNG
image10:
  - /insecure-deserialization-2/img10.PNG
---

Hello readers, welcome to part 2 of the series where we'll explore more about gadget chains.

### Gadget Chains

A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. An individual gadget may not directly do anything harmful with user input. However, the attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage. 

#### ysoserial

One such tool for Java deserialization is ["ysoserial"](https://github.com/frohoff/ysoserial). This lets you choose one of the provided gadget chains for a library that you think the target application is using, then pass in a command that you want to execute. It then creates an appropriate serialized object based on the selected chain.

### Exploiting Java Deserialization with Apache Commons

Not all of the gadget chains in ysoserial enable you to run arbitrary code. Instead, they may be useful for other purposes. For example, you can use the following ones to help you quickly detect insecure deserialization on virtually any server:

  1. The `URLDNS` chain triggers a DNS lookup for a supplied URL. Most importantly, it does not rely on the target application using a specific vulnerable library and works in any known Java version.
  2. `JRMPClient` is another universal chain that you can use for initial detection. It causes the server to try establishing a TCP connection to the supplied IP address.

Payload:

Java version 16 and above:

```bash
java \
 --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED\
 --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED\
 --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED\
 -jar ./ysoserial.jar <payload> 'command'
```

  
Java version 15 and below:

```bash
java -jar ysoserial-all.jar <payload> 'command' | base64
```

Observe that the session cookie contains a serialized Java object

<figure>
<img src="{{ page.image1 }}" alt="">
<figcaption>Fig 1. Session Cookie</figcaption>
</figure>

Generates a Base64-encoded serialized object containing your payload

<figure>
<img src="{{ page.image2 }}" alt="">
<figcaption>Fig 2. Decode and Generate Payload</figcaption>
</figure>

Replace your session cookie with the malicious one you just created. Select the entire cookie and then URL-encode it

<figure>
<img src="{{ page.image3 }}" alt="">
<figcaption>Fig 3. Resend Encoded Payload</figcaption>
</figure>


### PHP Generic Gadget Chains

Most languages that frequently suffer from insecure deserialization vulnerabilities have equivalent proof-of-concept tools. For example, for PHP-based sites you can use "PHP Generic Gadget Chains" [(PHPGGC)](https://github.com/ambionics/phpggc).


Notice that the token is actually a serialized PHP object, signed with a SHA-1 HMAC hash

<figure>
<img src="{{ page.image4 }}" alt="">
<figcaption>Fig 4. Session Cookie</figcaption>
</figure>

<figure>
<img src="{{ page.image5 }}" alt="">
<figcaption>Fig 5. Decoded token</figcaption>
</figure>

Notice that:

  1. The error message reveals that the website is using the Symfony 4.3.6 framework.
  2. The /cgi-bin/phpinfo.php debug file contains a secret_key.

<figure>
<img src="{{ page.image6 }}" alt="">
<figcaption>Fig 6. Exposed Framework</figcaption>
</figure>

<figure>
<img src="{{ page.image7 }}" alt="">
<figcaption>Fig 7. Secret Key</figcaption>
</figure>

Payload:

```bash
./phpggc <payload> exec 'command' | base64
```

<figure>
<img src="{{ page.image8 }}" alt="">
<figcaption>Fig 8. Creating Payload</figcaption>
</figure>

You now need to construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier. You can use the following PHP script to do this.

```PHP
<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
```

<figure>
<img src="{{ page.image9 }}" alt="">
<figcaption>Fig 9. Constructing Cookie</figcaption>
</figure>

Replace your session cookie with the malicious one you just created, then send the request to execture your command

<figure>
<img src="{{ page.image10 }}" alt="">
<figcaption>Fig 10. Resend Encoded Payload</figcaption>
</figure>

### Exploiting Ruby Deserialization Using a Documented Gadget Chain

There may not always be a dedicated tool available for exploiting known gadget chains in the framework used by the target application. In this case, it's always worth looking online to see if there are any documented exploits that you can adapt manually. Tweaking the code may require some basic understanding of the language and framework, and you might sometimes need to serialize the object yourself, but this approach is still considerably less effort than building an exploit from scratch.








IB: PortSwigger
