# Overview

IEEE 802.11i was aimed to improve the security from older versions but this
was released more than 2 decades ago and have several weakness. One of which
is an attacker can easily intercept the 4-way handshake which is used to
exchanged the cryptographic keys between a station and access point. Once
captured, attacker can perform dictionary attack against the PSK and MIC to
recover the wifi passphrase.

This tool demonstrates that attack by scanning for nearby APs, targetting
the clients and performing deauthentication attack to capture a 4-way
handshake. The tool will extract the different keys from the capture and
perform an offline dictionary attack.

This contains 2 custom modules for performing the attack - a network module
for executing tasks such as injecting frames and a crypto module that
recovers the MIC and other keys from the handshake.

# Usage

You can see the help menu by passing `-h` to the script. But before doing that,
be sure to install first the modules from the requirements file.

# Youtube Video

I create a video that will show you the thought process on how this tool was
created. You will learn different things like wifi networking, cryptography,
and programming.

https://youtu.be/FguOLGPkEjg?si=-XO0UT022V5sqi1u
