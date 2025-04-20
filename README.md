# OS-Hardening



### Table of Contents

- **[Introduction](#introduction)**
  * [Status](#status)
  * [Todo](#todo)
  * [Prologue](#prologue)
  * [Levels of priority](#levels-of-priority)
  * [OpenSCAP](#openscap)
- **[Preparation and Installation 🛡️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#preparation-and-installation-%EF%B8%8F)**
  * [Protecting a Newly Installed Machine from Network Threats](#separate-partitions)
  * [Set a BIOS/Firmware Password 🔒](#restrict-mount-options)
  * [Configure The Device Boot Order To Prevent Unauthorized Booting From Alternate Media](#polyinstantiated-directories)
  * [Disable USB Usage](#shared-memory)
  * [Use the latest version of Ubuntu possible](#encrypt-partitions)
  * [Lock Physical Console Access](#ballot_box_with_check-summary-checklist)
- **[Filesystem Configuration](#filesystem-configuration-)**
  * [Create a separate partition with the `nodev`, `nosuid`, and `noexec` options set for `/tmp`](#create-a-separate-partition-with-the-nodev-nosuid-and-noexec-options-set-for-tmp--)
  * [Create separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home`](#create-separate-partitions-for-var-varlog-varlogaudit-and-home-)
  * [Bind mount /var/tmp to /tmp ](#bind-mount-vartmp-to-tmp-)
  * [Set `nodev` option to /home](#set-nodev-option-to-home)
  * [Set nodev, nosuid, and noexec options on `/dev/shm`](#set-nodev-nosuid-and-noexec-options-on-devshm)
  * [Set sticky bit on all world-writable directories](#set-sticky-bit-on-all-world-writable-directories)
  * [Enable Hard/Soft Link Protection](#enable-hardsoft-link-protection)
  * [Disable Uncommon Filesystems](#disable-uncommon-filesystems)
  * [Lock The Boot Directory](#lock-the-boot-directory)
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**
- **[Physical Access](#physical-access)**

