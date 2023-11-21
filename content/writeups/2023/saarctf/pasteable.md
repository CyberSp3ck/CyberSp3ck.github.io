+++
author = "Matteo Golinelli & Michele Grisafi"
title = "[saarCTF 23] Pasteable Writeup"
date = "2023-11-20"
description = "Writeup for the Pasteable challenge of the saarCTF 23"
tags = [
    "writeup",
    "ctf",
    "web"
]
+++

## Challenge Description

The challenge was a web application that allowed users to create and share password-protected notes. The application is written in PHP and uses a MySQL database to store the notes.

When creating a note, the user must enter a title, some content, and a password that is used to encrypt the note. The note is then stored in the database and the user is given a link to share the note with others. When opening the link, the user is asked to enter the password to decrypt the note. The link is composed of an ID and a checksum:
`http://host:port/reveal/?id=<ID>&checksum=<CHECKSUM>`

The ID is computed using the PHP [`uniqid()`](https://www.php.net/manual/en/function.uniqid.php) function. The documentation states that "This function does not generate cryptographically secure values, and must not be used for cryptographic purposes, or purposes that require returned values to be unguessable.".

Even if an attacker can guess the ID of a note of another user, they cannot read the content without its password. Nevertheless, we replaced this unsafe function with [`random_int()`](https://www.php.net/manual/en/function.random-int.php)

A registered user can read the content of its notes without entering the password.

## Vulnerability

The functionalities of the web application are restricted to logged in users. The registration and login processes are handled by the same form and are both composed of two separated steps:

1. **Crypto challenge**:
    In this first step, independently on whether the user is registering or signin into an existing account, the client will send the username to the `/func/challenge.php` endpoint. This server checks whether the user is already registered and, in this case, it:

   1. Generates the **challenge**: a weak 6 characters random string.
   2. Stores the challenge in the PHP `$_SESSION` variable, that is persistent across different HTTP requests.
   3. Sends the challenge encrypted with the hash of the user password (fetched from the database) in the HTTP response.

    If the user is not yet registered (i.e., not found in the database), the server sends an HTTP response the string "**ok**" as body.

2. **Login and registration**:
    Depending on the server response, the client (i.e., the JavaScript `submitLogin()` function) will either try to sign up or sign in the user.

    - To **register** a new user, it sends the *username* and the *hash of the password* to the `func/registration.php` endpoint, that stores it in the database.
    - To **login** an existing user, the client receives the challenge and tries to solve it by using the password entered by the user. Once the solution has been computed, it sends it to the `/func/login.php` endpoint, together with the username. The **vulnerability** lays in this login process. Specifically, the server does not check that the username that it receives is the same as the one for which the challenge was generated, but only checks that a username and a solution are included in the request. If the solution is equal to the one that was stored in the `$_SESSION` variable in *step 1*, then it logs the provided username in.

## Exploitation

Exploiting the vulnerability is conceptually easy: an attacker registers a user, solves the login challenge using its password, and sends the solution together with a different username that it wants hijack. The server receives the solution, checks whether it is correct, and logs the received username in.

### Exploit

The game server places the flags in the web application by registering a user and storing the flag in a note. The name of the registered users are the flag IDs that could be found by requesting the URL <https://scoreboard.ctf.saarland/attack.json>.

For each target machine, we first download the list of flag IDs. Then, we **register a user** on the target application by directly sending the username and the hashed password to the registration endpoint.

```python
pass_hash = hashlib.sha256("OurSecretPassword!".encode('utf-8')).hexdigest()
register_response = session.post(register_url, data={"username": my_username, "password": pass_hash})
```

**Note**: *to make our registration unrecognizable from those made by the game server, we use a randomly selected flag ID from another target as the username*.

Then, for each flag ID of the target (i.e., username):

1. We send a login request to the target application with the username that we registered and receive a **challenge**.

2. We solve the challenge using the password of our registered user to get the **solution**.

    ```python
    challenge_response = session.post(challenge_url, data={"username": my_username})
    challenge = challenge_response.text

    key = bytes.fromhex(pass_hash)
    iv = bytes.fromhex(pass_hash[:32])
    ciphertext = bytes.fromhex(challenge)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = cipher.decrypt(ciphertext)

    solution = decrypted_bytes.decode('utf-8', 'ignore').strip()
    ```

3. We send the solution to the target application, setting as username the flag ID that we want to retrieve.

    ```python
    login_response = session.post(login_url, data={"username": flag_ID, "solution": solution})
    ```

4. We visit the homepage of the application that shows all the notes of the logged user. The flag is in the content of the note. We use BeautifulSoup to parse the page and extract the flag.

    ```python
    soup = BeautifulSoup(homepage_response.text, 'html.parser')
    flag = soup.find("p", class_="card-text").text
    ```

## Patch

To properly patch the login process without modifying the APIs and the client-side code (as the game server directly performed the requests to the endpoints), we modified the code on the server-side.

First, we bound the challenge to the username (i.e., the challenge owner) by storing the **username** into a separate PHP `$_SESSION` variable:

```php
$_SESSION['challenge'] = $random_string;
$_SESSION["username"] = $username;
```

Upon login, the server will check that both the challenge solution and the received username are the same as the ones saved in the `$_SESSION` variable during the first step:

```php
if (
        (strcmp($_POST['solution'], $_SESSION['challenge']) != 0) &&
        (strcmp($_POST['username'], $_SESSION['username']) != 0)
    ) {
    header('HTTP/1.0 403 Forbidden');
    die("Invalid request");
}
```

Moreover, we changed the `generateChallenge()` function to have a higher strength (i.e., the length of the challenge) and to not seed PHP's *Mersenne Twister Random Number Generator* (`mt_rand()`) with the current `time()` because, according to the documentation and a [StackOverflow answer](https://stackoverflow.com/a/11358829), this is already done by PHP based on "the current timestamp, the PHP process PID and a value produced by PHP's internal [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator)", that is safe enough for our purposes.

Finally, we check that `$_POST['solution']` and `$_POST['username']` are not arrays, because on our traffic analyzer we saw that some attacking teams were stealing our flags by sending an array as username and solution. The patch effectively stopped this attack, but we did not investigate this issue further.

```php
if(is_array($_POST['username'] || is_array($_POST['solution'])){
    header('HTTP/1.0 403 Forbidden');
    die("Invalid request");
}
```
