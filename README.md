# Lacida [^1]

**Send private, encrypted messages from Mac to iPhone**

In short it is private and secure way of sending messages from Mac (or not Mac) to iPhone. I am sending to my own iPhone in this case but you can send messages to friends etc.

No 3-rd party aka Apple or Facebook involved and no backdoors open to state agents. Just Python code that you can verify yourself...

It is encrypting a file with AES, putting encrypted ile on Google Drive and sending Pushover notification with link to Editorial workflow that will get encrypted file from GDrive and decrypt.

* You will need [Editorial app on iPhone](http://omz-software.com/editorial/) (it is a note-taking app with Python support)

* And [my Editorial Workflow for decrypting](http://www.editorial-workflows.com/workflow/5833682849890304/xu7eKvr4GJM) on iPhone. You can/should review simple Python code inside Editorial app or [on workflow page here](http://www.editorial-workflows.com/workflow/5833682849890304/xu7eKvr4GJM).

* And you will need [Pushover API](https://pushover.net/api) user and application token stored in keychain.

```
security add-internet-password -a 'Token' -s 'pushover.net' -w 'MY USER KEY...'

security add-internet-password -a 'Python' -s 'pushover.net' -w 'MY APPLICATION TOKEN...'

```

* And also need installed and authorized [gdrive app](https://github.com/prasmussen/gdrive) 

```brew install gdrive```

* And you may store your default encryption key in keychain (instead of passing as a parameter and leaving traces in shell history)

```security add-internet-password -a 'key' -s 'encrypt.decrypt' -w 'MY ENCRYPTION KEY' ```

Review encrypt2iPhone.py and fill in the gaps (device name) if you need.

I have made simple Automator service that encrypts and sends selected file. Simple.

[1] Lacida was a name of Polish reverse engineered copy of German Enigma encryption device built in 1933 and used for decrypting Enigma messages until 1939. Name is a short of colonel Langer, lieutenat Ciężki and engineer Danilewicz.
