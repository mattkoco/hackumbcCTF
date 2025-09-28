
You are presented with a web app and given the hint "Have you tried enumerating the site?" Enumerating a site can include a variety of things including finding hidden directories, checking for XSS, SSTI, and command injection. Most commonly, researchers attempt to enumerate hidden directories first to get an idea of their attack surface. 

The most popular tool for enumerating is dirbuster, which is a standard package on Kali linux. Start by opening up the program and inputting the IP  and choosing a wordlist. Kali linux by default has many wordlists found in `/usr/share/dirbuster/wordlist`

Once executed, you can see that there is a directory not visible to the public called `docs.html`

![Image](/hackathon/image.png)





`document.cookie = "tg_session=<YWRtaW46YWRtaW46dW1iYzE5NjY=>; Path=/";`
`location.href = "/admin";`
