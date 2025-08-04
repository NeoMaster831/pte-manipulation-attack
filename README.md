# PTE Manipulation Attack

The PTE Manipulation Attack is a technique used to compromise a system by modifying arbitrary page table entries. This attack method is fundamental yet possesses numerous possibilities.

# Prerequisite

1. The attacker can **bitwise** write arbitrary values to arbitrary kernel addresses.
2. The target environment is either Windows or BSD-based.
3. If the environment is Linux, the following conditions must be met:
    1. The attacker knows the CR3 value.
    2. The attacker knows the value of the `PAGE_OFFSET` symbol.

There may be narrower attack vectors. If you discover one, please report it. Your contribution would be highly appreciated. Regarding Linux, due to the rarity of scenarios where CR3 can be leaked and the randomization of `PAGE_OFFSET` by KASLR, it is challenging to satisfy these conditions. Hence, Linux-specific details are not thoroughly covered here.

### Additional Information

1. If arbitrary reading is possible, the attack can still be conducted without bitwise writing, as byte-level writing is sufficient.
2. Write failures may cause the system to crash. In Windows, each write attempt has approximately a 0.390625% chance of success. Conversely, if the system does not crash upon write failure, the success rate of the attack is 100%. This aspect can be ignored for BSD-based systems.
3. If a non-destructive write oracle (XOR, AND, OR, ADD, SUB, …) is available, bitwise writing is not mandatory.

## Files
- `krnl`: A deliberately vulnerable driver designed to demonstrate the PTE Manipulation Attack.
- `ex`: Exploit code leveraging the vulnerability in `krnl` to compromise the system.
- `explain`: Documentation describing this attack in Korean.

## TODO
It is possible to gain a shell even without the `Verify` menu, but my technical skills were insufficient to implement this. Pull requests for implementing this would be greatly appreciated. The methodology is as follows:

Modifying the `U/S` bit of the NT kernel's PTE to extract the `Token` of `PsInitialSystemProcess` is extremely dangerous due to SMAP. Thus, arbitrary address reading (AAR) of NT kernel data is impossible, necessitating a different approach.

- Identify an appropriate, rarely-used function listed in the SSDT, enable the `W` bit on its page, and hook it.
- Generally, write shellcode to transfer the `Token` from `PsInitialSystemProcess` to the current process. If the chosen function is insufficient in length, hooking should be employed.
- For hooking, allocate a user-mode buffer, write desired shellcode to it, and clear the `U/S` bit to disable SMAP.
    - In most cases, hooking is preferable due to reduced execution time and lower race condition risk.
- Trigger the hooked function to execute desired code in kernel mode.

After extensive consideration, this approach appears optimal. If you have any innovative alternative suggestions, please report them. Your input would be greatly appreciated.

This method triggers PatchGuard. Thus, all operations must be performed and reverted within 2 minutes.

### Lastly
The provided exploit and details may vary significantly between different computers. For instance, on my machine, the NT kernel loads at physical address `0x100400`, but this will likely differ on other systems. Please refer to `explain` for further details.