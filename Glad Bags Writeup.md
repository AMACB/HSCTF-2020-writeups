# Glad Bags Writeup

>Poortho made some hard pwn for y'all. It's so hard, you don't get any input.

(Preface: This problem was not hard like other problems where you need a large amount of sufficient knowledge (heap pwn), but very lengthly and drawn out, like the Harry Potter series.)

Well, on the bright side, this is forensics, not pwn (we did not manage to solve poortho's actual pwn...)
We first get the download glad_bags, which running file on it says is an elf,  and running the program and ghidra analysis points at the program seemingly just being a kind of "hello world."
However, a "hello world" program that prints a string should not take a whopping 13 MB...so something fishy is contained within the binary.

Running binwalk, we find the stinky fish poortho placed in:
```8304          0x2070          7-zip archive data, version 0.4```
After extracting, we are met with an almost 13 MB file, proving that printing a string doesn't take much of anything...
Opening the archive, we are met with a familiar name: angr (which I have been meaning to learn...), and it looks like an archive of the source code.

There were two methods to the next step:
1. The thorough method: angr (and everything that follows) has unmodified free downloads that "closely" (where it matters) match poortho's. Extract both archives into separate directories and use `diff -rq dir1 dir2` to get the list of changes that matter. I used this at the beginning before I realized...
2. The lazy method: file/folder size is key. The original binary was way too bloated, hinting that it contained the angr archive. Even the angr archive was bloated, about twice as large as GitHub's version. The 7zip GUI conveniently lists the file/folder sizes of the archive, so you can hone in on the anomalously large areas.

Using either method, the culprit can be found as another 7z file at angr > afl > afl.7z
The challenge continues in the nested format:

1. afl contains pwntools (GitHub dev branch). Setup.py is way too large. If you tried opening it and scrolling down, you'd be greeted with this...
![](https://cdn.discordapp.com/attachments/717493157440258048/717839149868122142/unknown.png)
Open at your own risk! This picture was taken just before Notepad++ crashed. Same fate with standard notepad and even vim. Poortho also said he had issues during this step in his test solve... This is hex, which you can manually convert back into characters to get the binary file, or just use this tool after deleting all the python surrounding it (don't forget the parentheses at the end of the file...good luck with that!): <http://tomeko.net/bin/hex_to_file/hex_to_file.exe>. With that, we get the next 7z.
2. Audacity: This one would have had to compare to GitHub source since the first sizes when opening don't give much away, but a cursory peek through the files showed a suspiciously-named suspicious.ny in the plugin folder, with a suspiciously large size compared to the others. Opening the file appears to first be standard text, but disappears at line 58, beginning with PK, the magic header for zip files, giving us...
3. 7-zip: actually, this is the 7-zip Extra version, and unlike the past ones, it is not source.

7-zip is the final destination in nested archives, tested through binwalking through the larger files. The file of interest is aarch64/7za.exe due to several red flags:
1. x64 and aarch64 usually mean the same thing, and shouldn't be present together.
2. Looking into them, aarch64 has a 7za.exe and a 7za.exe.bak. Highly unusual for released software to keep backup files of binaries like that. And 7za.exe is just 10 bytes larger.
3. Probably the biggest giveaway, all the other files in those two folders were last modified in 2019, while this one was May 28, a few days before the ctf, and it sticks out like a sore thumb in 7zip.

![](https://cdn.discordapp.com/attachments/717493157440258048/718657504845889576/unknown.png)

Diffing the FOI and the backup shows an interesting string: `MZWGCZ33MRXW45C7M5SXIX3NMFSF6Z3FORPWO3DBMRPWK6T5` I have no idea what encoding that is, but maybe CyberChef does...

![](https://cdn.discordapp.com/attachments/717493157440258048/718665238634823720/unknown.png)

Flag: `flag{dont_get_mad_get_glad_ez}`
Also, if you take out the modified 7z.exe and rename the backup, hashing the x64 and aarch64 folders reveals that they are identical...not sure why both were in there.
