+++
author = "Carlo Ramponi"
title = "[SrdnlenCTF 23] Koenigsberg Writeup"
date = "2023-11-20"
description = "Writeup for the Koenigsberg challenge of the srdnlenCTF 23"
tags = [
    "writeup",
    "ctf",
    "reverse"
]
+++

As the name of the challenge suggests, we are dealing with graphs ([https://en.wikipedia.org/wiki/Seven_Bridges_of_K%C3%B6nigsberg](https://en.wikipedia.org/wiki/Seven_Bridges_of_K%C3%B6nigsberg)).

There will probably be a graph implemented in some way inside the binary, and the goal will probably be to traverse each and every node only once.

## Reverse-engineering

The challenge comes in the form of a x86_64 ELF binary, with symbols.
The main function is pretty simple:

```c
undefined8 main(void) {
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char input [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,NULL);
  setbuf(stdin,NULL);
  puts("Send me the damn flag.\n\n");
  fgets(input,0x46,stdin);
  sVar2 = strcspn(input,"\r\n");
  input[sVar2] = '\0';
  iVar1 = check_path(input);
  if (iVar1 == 0) {
    puts("Checks out to me. Just submit it.");
  }
  else {
    printf("You got something wrong.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The input given to the program is passed to the `check_path` function, which returns `0` if the input is correct, and `1` otherwise.

The input is considered correct if it is the flag.
From here, we understand that we have to reverse the `check_path` function.

The function is huge, and Ghidra is not able to decompile it correctly, so we'll have to do it manually.
Here is anyway how Ghidra presents it:

```c
undefined8 check_path(byte *input) {
  undefined *puVar1;
  undefined8 uVar2;
  undefined *puVar3;
  byte *input_copy;
  int node_counter;
  undefined *functions [16000];
  
                    /* This loop simply does: SUB RSP, 0x1F440 */
  puVar1 = &stack0xfffffffffffffff8;
  do {
    puVar3 = puVar1;
    *(undefined8 *)(puVar3 + -0x1000) = *(undefined8 *)(puVar3 + -0x1000);
    puVar1 = puVar3 + -0x1000;
  } while ((undefined **)(puVar3 + -0x1000) != functions + 0x82);
  *(undefined8 *)(puVar3 + -0x1448) = 0x15f265;
  memcpy(functions,::functions,0x1f400);
  visited[0] = 1;
/* WARNING: Could not recover jumptable at 0x0015f324. Too many branches */
            /* WARNING: Treating indirect jump as call */
  uVar2 = (*(code *)functions[(int)(char)(*input ^ 0x35) % 16000])();
  return uVar2;
}
```

- The first part of the function is simply setting up the stack depth, which is `0x1F440` bytes.

- Then, it copies the `functions` array (this is how I called it) into the stack.
  
  This array contains pointers to different part of this function, and will be used later to jump to different "nodes" based on the given input.

- Then, it sets the first element of the `visited` array to `1`.

  The `visited` array is a global array of 1000 elements, which is used to keep track of the nodes that have been visited.

- Finally, the first jump is performed, which selects the next node to jump to, based on the first character of the flag.

The first thing to do is to export the `functions` array so that is can be analyzed later.
The array contains `16000` elements, each one of them pointing to a part of the function, but since there are only `1000` nodes (as we can understand from the size of the `visited` array), some pointers are repeated.
This means that there could be different ways to reach the same node, and we have to find the correct one.

By taking a look at some of the "sub-functions" pointed by the `functions` array, we can see that they are all similar.

Here is an example:

```c
undefined8 UndefinedFunction_001650a5(void) {
  int iVar1;
  undefined8 uVar2;
  long unaff_RBP;
  long in_FS_OFFSET;
  
  if (visited[114] != 1) {
    visited[114] = visited[659];
    iVar1 = *(int *)(unaff_RBP + -0x1f41c);
    *(int *)(unaff_RBP + -0x1f41c) = iVar1 + 1;
    *(byte *)(unaff_RBP + -0x1f421) =
         *(byte *)(*(long *)(unaff_RBP + -0x1f438) + (long)(iVar1 % 0x44)) ^ 0x31;
    *(undefined8 *)(unaff_RBP + -0x1f418) =
         *(undefined8 *)
          (unaff_RBP + -0x1f410 + (long)((*(char *)(unaff_RBP + -0x1f421) + 0x720) % 16000) * 8);
    if (*(int *)(unaff_RBP + -0x1f41c) < 0x3e9) {
/* WARNING: Could not recover jumptable at 0x00165177. Too many branches */
                /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)(unaff_RBP + -0x1f418))();
      return uVar2;
    }
  }
  if (*(long *)(unaff_RBP + -8) == *(long *)(in_FS_OFFSET + 0x28)) {
    return 1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

- The first check is very useful to us: it shows that this sub-function represents the node `114`, and that the only "legal" way to reach it is from the node `659`.

- Also, from this code we can undestand how the next node is chosen, in this case it is:

  ```c
  functions[((input[counter % 0x44] ^ 0x31) + 0x720) % 16000]
  ```

  Stack variables are not recognized by Ghidra:
  - `$rbp-0x1f438` contains the address of the `input` provided by the user.
  - `$rbp-0x1f41c` contains a counter variable, which is incremented at each iteration and goes from `0` to `0x3e8` (1000).
  - `$rbp-0x1f421` is temporary variable, which is used to store the result of the operation `input[counter % 0x44] ^ 0x31`.
  - `$rbp-0x1f410` contains a copy of the `functions` array
  - `$rbp-0x1f418` is a temporary variable containing the address of the next node to jump to.

The next thing to do is to parse all the sub-functions, to understand how each node choses the next one, in particular every jump comes in the form of:

```c
functions[((input[counter % 0x44] ^ A) + B) % 16000]()
```

So we'll only need to find the values of `A` and `B` for each node.
After some analysis, it turns out that `B` is always the number of the node multiplied by `16` (e.g. `114 * 16 = 1824 (0x720)`), so we'll just need to find `A`.

Another important thing to find is the constraint on each node, which is the node we **have** to come from to reach the current one.
That can be inferred from the assignment of the `visited` array, which is always in the form:

```c
visited[current_node] = visited[previous_node];
```

Finally, the last node (`999`), instead of jumping to another node, will check if the `visited` array contains only `1`s, and if so, it will return `0`, otherwise it will return `1`.

## Solution

There are hundreds of right ways to parse the assembly code, but I decided to go with the dumb one.
I dumped the disassembled `check_path` function using `gdb` and I wrote a python script that parses it and extracts the information we need.

```python
import re

with open("check_path", "r") as f:
    disass = f.read()

matcher = re.compile(r'<visited\+(\d+)>.*\n.*<visited\+(\d+)>.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*\n.*xor.*eax,0x([0-9a-fA-F]+)', re.MULTILINE)

# match every occurrence of a regular expression in disass
matches = matcher.findall(disass)
edges = [(int(a) // 4, int(b) // 4, c) for a, b, c in matches]

print("0 -> 492 (0x67)")
for edge in edges:
    print(f"{edge[0]} -> {edge[1]} (0x{edge[2]})")
```

This produces a simpler representation of the graph, only encoding the incoming edge of each node and the value of `A` that will be used to compute the next one.
Then, also the `functions` array will be parsed to match the value of the expression `((input[counter % 0x44] ^ A) + B) % 16000` with the corresponding node.

Having all this information, and given the current node, we can compute all the possible characters that can be used to reach the next "correct" node.

> **_NOTE_**: The graph has 1000 nodes, but the flag is much shorter (remember the modulo 0x44?), so there can probably be multiple characters to go from one node to another, but only one of them will respect all the following edges (every character of the flag will be used to compute multiple edges).

Here is the python function that computes the possible characters:

```python
def guess_next_char(current_node):
    next_node = ee[current_node.to]
    guesses = []
    for i in next_node.indexes:
        guess = (i - (current_node.f * 16)) ^ current_node.xor
        if guess >= 0 and guess < 256 and chr(guess) in char_pool:
            guesses.append(chr(guess))
    return guesses
```

Here:
- `ee` is a dictionary containing the edges of the graph, indexed by their number.
- Each edge contains the id of the `next` (`to`) node, the id of the `previous` (`f`) node, the value of `A` (`xor`) which will be used to compute the index for the `functions` array, and a list of indexes of the `functions` array that contain the address of the node itself (`indexes`) (so the values with which you can reach this node).

The possible guesses can be reduced by only selecting printable characters, and possibly by checking which one eventually leads to the last node.
But it was actually easier to just print them all and manually select the one that was making sense (since the flag is something senseful).

So here is the final script:

```python
possible_flags = [""]
for _ in range(100):
    next_char = guess_next_char(current_node)
    if len(next_char) == 0:
        # something went terribly wrong
        break
    possible_flags = [f + c for f in possible_flags for c in next_char]
    print("\n".join(possible_flags))
    current_node = ee[current_node.to]
```

The flag is: `srdnlen{uhm_technically_this_is_a_hamiltonian_cycle_:nerd:_0ff829a6}`