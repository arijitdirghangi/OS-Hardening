# OS-Hardening



### Table of Contents

- **[Introduction](#introduction)**
  * [Status](#status)
  * [Todo](#todo)
  * [Prologue](#prologue)
  * [Levels of priority](#levels-of-priority)
  * [OpenSCAP](#openscap)
- **[Preparation and Installation 🛡️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#preparation-and-installation-%EF%B8%8F)**
  * [Protecting a Newly Installed Machine from Network Threats](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#protecting-a-newly-installed-machine-from-network-threats--)
  * [Set a BIOS/Firmware Password 🔒](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-a-biosfirmware-password--)
  * [Configure The Device Boot Order To Prevent Unauthorized Booting From Alternate Media](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#configure-the-device-boot-order-to-prevent-unauthorized-booting-from-alternate-media-)
  * [Disable USB Usage](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-usb-usage)
  * [Use the latest version of Ubuntu possible](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#use-the-latest-version--of-ubuntu)
  * [Lock Physical Console Access](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#lock-physical-console-access-)
- **[Filesystem Configuration](#filesystem-configuration-)**
  * [Create a separate partition with the `nodev`, `nosuid`, and `noexec` options set for `/tmp`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#create-a-separate-partition-with-the-nodev-nosuid-and-noexec-options-set-for-tmp--)
  * [Create separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#create-separate-partitions-for-var-varlog-varlogaudit-and-home-)
  * [Bind mount /var/tmp to /tmp ](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#bind-mount-vartmp-to-tmp-)
  * [Set `nodev` option to /home](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-nodev-option-to-home)
  * [Set nodev, nosuid, and noexec options on `/dev/shm`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-nodev-nosuid-and-noexec-options-on-devshm)
  * [Set sticky bit on all world-writable directories](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-sticky-bit-on-all-world-writable-directories)
  * [Enable Hard/Soft Link Protection](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-hardsoft-link-protection)
  * [Disable Uncommon Filesystems](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-uncommon-filesystems)
  * [Lock The Boot Directory](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#lock-the-boot-directory)
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**

