---
layout: post
title:  "Android Root Detection Bypass"
date:   2023-09-18 09:29:20 +0700
categories: jekyll update
usemathjax: true
tag:
  - tips
  - android
  - mobile
image: 
  - /evading-root-detection/img1.PNG
image1:
  - /evading-root-detection/img2.PNG
image2:
  - /evading-root-detection/img4.PNG
image3:
  - /evading-root-detection/img3.PNG
image4:
  - /evading-root-detection/img5.PNG
---

Helloo readers!

If you are currently reading this, it is likely that you are aware of the disconcerting nature of encountering root detection safeguards during Android black box assessments.

Before going into a more in-depth discussion of reverse engineering, I've presented a range of beginner-friendly methods that are highly effective in real-world penetration testing and not just some insecure Android applications.

### Magisk Hide Module

If your device has been rooted using Magisk, you can utilize the MagiskHide feature within the Magisk application.

1. Download the [Magisk Hide Module](https://github.com/HuskyDG/MagiskHide) on Github and install it from storage.
2. Turn on the MagiskHide Module.
3. Go to Settings > Enable Zygisk > Enable Enforce Deny List > Configure DenyList > Choose the Application.

<figure>
<img src="{{ page.image }}" alt="MagiskHide">
<figcaption>Fig 1. Magisk Hide</figcaption>
</figure>

### Community Script and Tool

When working with Frida, the first crucial step is to set up the Frida Server on your Android phone.

This can easily be done by installing [Frida Server Magisk Module](https://github.com/ViRb3/magisk-frida). Turn the module on and restart your phone.

<figure>
<img src="{{ page.image1 }}" alt="Frida Server">
<figcaption>Fig 2. Frida Server</figcaption>
</figure>

**Always remember that Frida could not run concurrently with MagiskHide, it is important to disable all the options done from the previous tutorial to try these steps.**


#### Frida Script

Here comes the most and widely used root detection bypass method. 

1. Connect your USB Cable onto your device.
2. Running the Frida script will spawn the targeted application. 

Here is my most used community [script](https://gist.github.com/pich4ya/0b2a8592d3c8d5df9c34b8d185d2ea35) to bypass root detection that uses any protections in general.

```bash
frida -U -f package.name -l root-detection.js
frida -l root-detection.js -U -n 'appname'
```


<figure>
<img src="{{ page.image2 }}" alt="Frida Script">
<figcaption>Fig 3. Frida Script</figcaption>
</figure>


#### FridaAntiRootDetection

The next [Root Evasion Tool](https://github.com/AshenOneYe/FridaAntiRootDetection) that I wanted to share with you is Frida Anti Root Detection by AshenOneYe. This tool works by attaching into the application's processes.

All it takes is changing the target's package name in the Python script, and you're all set! It can be quite entertaining to dabble in script kiddie activities, but remember that responsible and ethical use of your skills is essential to ensure you're contributing positively to the digital community. 😁

```bash
import frida
import os

device = frida.get_usb_device()
print(device)

target = "CHANGE_HERE"
```


<figure>
<img src="{{ page.image3 }}" alt="FridaAntiRootDetection">
<figcaption>Fig 4. FridaAntiRootDetection</figcaption>
</figure>

#### Objection

Last but not least is Objection, besides providing root bypass capability, it also offers many more versatile usages such as runtime mobile exploration.

```objection --gadget "package" explore```

<figure>
<img src="{{ page.image4 }}" alt="Objection">
<figcaption>Fig 5. Objection</figcaption>
</figure>

So that’s it guys, may this methods help you to get rid of your root detection problem.

See you on my next blog post!
