# packet-ge-srtp

v0.0.1

# Overview

This is a (rather quick-and0dirty) Wireshark Lua dissector for the GE-FANUC Service Request Transfer Protocol.
This is a private protocol with minimum documentations, but you can still find some lying around over the internet.
For more information, see the [References](#references) section.

# Status

The dissector is mostly complete, except for the following:
- no support for multi-packet response message (because I'm lazy)
- no support for SNPX parsing (they're text, anyway.)

# Installation

## Linux

Copy or symlink the `packet-ge-srtp.lua` file to either Wireshark global (`/usr/(local)/share/wireshark/plugins`) or per-user (`$HOME/.config/wireshark/plugins` or `$HOME/.wireshark/plugins`) plugin directory.

## Windows

Copy or symlink the `packet-ge-srtp.lua` file to either Wireshark global (`%WIRESHARK%\plugins`) or
per-user (`%APPDATA%\Wireshark\plugins`) plugin directory.

## Mac

I dunno, don't own a Mac.

# Compatible Wireshark versions

This dissector has been developed and tested with Wireswhark v3.x.

# Disclaimer

**The authohr of this software is not affiliated with GE or FANUC Corporation in any way. All trademarks and registered trademarks are property of their respective owners, and company, product and service names mentioned in this readme or appearing in source code or other artifacts in this repository are used for identification purposes only.**

**Use of these names does not imply endorsement by either GE nor FANUC Corporation.**

# References

1. https://sourceforge.net/projects/libopensrtp/ : ge-srtp C implementation
2. https://github.com/TheMadHatt3r/ge-ethernet-SRTP : ge-srtp python implementation
3. https://github.com/youk-wu/RobotIntelface : Open-source FANUC RobotDK (alpha stage)
4. https://github.com/Palatis/Palatis.Fanuc.RobotInterface : Open-source FANUC RobotDK (talks over ge-srtp and SNPX)
5. https://www.researchgate.net/publication/318925679_Leveraging_the_SRTP_protocol_for_over-the-network_memory_acquisition_of_a_GE_Fanuc_Series_90-30 : analyze of the ge-srtp protocol