# TrueGritVinyls

Category: Forensics/web

You are presented with a web app and given the hint "Have you tried enumerating the site?" Enumerating a site can include a variety of things including finding hidden directories, checking for XSS, SSTI, and command injection. Most commonly, researchers attempt to enumerate hidden directories first to get an idea of their attack surface. 

The most popular tool for enumerating is dirbuster, which is a standard package on Kali linux. Start by opening up the program and inputting the IP  and choosing a wordlist. Kali linux by default has many wordlists found in `/usr/share/dirbuster/wordlist`

Once executed, you can see that there is a directory not visible to the public called `docs.html`

![Image](/hackathon/images/image.png)


Visiting docs.html directs you to a docs screen


![Image1](/hackathon/images/image1.png)



The docs screen displays private information about how to set a cookie to give admin rights. This specific scenario of cookie signing is not secure as cookie signing usually requires a secret to protect the authenticity of a cookie and simply cannot be forged. In this case, there is no authentication and a threat actor can make a cookie from their own will. 

Below is a sample JS code sequence to get admin and redirect to the /admin endpoint.

`document.cookie = "tg_session=<YWRtaW46YWRtaW46dW1iYzE5NjY=>; Path=/";`
`location.href = "/admin";`


The /admin endpoint shows a google drive link which links to a file which contains a disk. 


The disk file is a standard vmdk file. Use `autopsy` or `FTK imager` to view the disk file. Once you have done some basic searching, you come across a wav file:


<img width="1026" height="353" alt="image" src="https://github.com/user-attachments/assets/5a37b407-ce96-438c-8657-2e5b49043e62" />





Export the WAV file. At first, you will hear a lot of static and noise which you may not recognized. This is SSTV! SSTV is a method of transmitting static images over radio waves by converting the image data into a series of audio tones. You can use many decoders online. Once decoded, you get the flag!

Final Flag: `hackUMBC{you_are_super_gritty_6767}`
