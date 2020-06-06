# Untitled Audio Challenge Writeup

> I hid an image into the waveform... recognize the magic numbers?

Looking at the waveform heavily zoomed in using Audacity, the first thing we notice is that the waveform values are nearly all positive. 

![Audacity Waveform](https://cdn.discordapp.com/attachments/717461073829298208/717513639166476338/unknown.png)

From here we can see that there is a surprising number of zeros, implying binary data alongside the hint. Checking the magic numbers of common file types, the heights of these waveforms also mostly match up with the magic numbers for a PNG file represented in hex. The waveform values are therefore encoding the binary data for a PNG, which will end up containing the flag.

Converting the waveform data to an array of 16 bit integers, we find that the values are clustered around multiples of 2048. By dividing by 2048 and rounding, we can convert the waveform to hex data, which we can then convert into raw binary data, generating a (gigantic) PNG.

Final PNG:

![Flag Image](https://cdn.discordapp.com/attachments/717461073829298208/717522936524963922/unknown.png)

Code:
```python
import scipy.io.wavfile

rate, amp_arr = scipy.io.wavfile.read('UAC.wav')

f = open('uac.png','wb')

for i in range(0,len(amp_arr),2):
	c = bytearray([int(amp_arr[i]/2048+0.5)*16 + int(amp_arr[i+1]/2058+0.5)])
	if i < 100:
		print(c)
	f.write(c)
f.close()
```
