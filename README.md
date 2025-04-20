### What is OS Hardening ? 
- OS Hardening refers to the process of securing an operating system by minimizing its attack surface. This involves: 
>  - Removing unnecessary services, packages, and dependencies to reduce potential security risks.
>  - Closing unused ports to prevent unauthorized access.
>  - Using minimal base images to limit vulnerabilities and reduce exposure.

<br/>

> I’ve created a basic OS Hardening checklist that covers essential security practices for Windows 11 and RHEL/Ubuntu systems. <br/>
> For now, I’ve focused on implementing and testing the hardening steps specifically on Ubuntu.

> The checklist includes practical steps I’ve performed, verified, and documented.
> You can find the detailed breakdown in the sections below:

<br/>

> 📥 You can download the OS Hardening checklists in Excel format:
> 
> - **[🐧 Linux OS Hardening Checklist](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Linux%20OS%20Hardening%20Checklist.xlsx)**  
> - **[🪟 Windows OS Hardening Checklist](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Windows%20OS%20Hardening%20Checklist.xlsx)**

---

### 📚 Table of Contents

- **[Preparation and Installation 🛡️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#preparation-and-installation-%EF%B8%8F)**
  * [Protecting a Newly Installed Machine from Network Threats](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#protecting-a-newly-installed-machine-from-network-threats--)
  * [Set a BIOS/Firmware Password 🔒](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-a-biosfirmware-password--)
  * [Configure The Device Boot Order To Prevent Unauthorized Booting From Alternate Media](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#configure-the-device-boot-order-to-prevent-unauthorized-booting-from-alternate-media-)
  * [Disable USB Usage](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-usb-usage)
  * [Use the latest version of Ubuntu possible](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#use-the-latest-version--of-ubuntu)
  * [Lock Physical Console Access](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#lock-physical-console-access-)
- **[Filesystem Configuration 📁](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#filesystem-configuration-)**
  * [Create a separate partition with the `nodev`, `nosuid`, and `noexec` options set for `/tmp`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#create-a-separate-partition-with-the-nodev-nosuid-and-noexec-options-set-for-tmp--)
  * [Create separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#create-separate-partitions-for-var-varlog-varlogaudit-and-home-)
  * [Bind mount /var/tmp to /tmp ](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#bind-mount-vartmp-to-tmp-)
  * [Set `nodev` option to /home](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-nodev-option-to-home)
  * [Set nodev, nosuid, and noexec options on `/dev/shm`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-nodev-nosuid-and-noexec-options-on-devshm)
  * [Set sticky bit on all world-writable directories](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-sticky-bit-on-all-world-writable-directories)
  * [Enable Hard/Soft Link Protection](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-hardsoft-link-protection)
  * [Disable Uncommon Filesystems](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-uncommon-filesystems)
  * [Lock The Boot Directory](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#lock-the-boot-directory)
- **[System Updates 🛡️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#system-updates-%EF%B8%8F)**
  * [Enable Unattended Security Updates on Ubuntu](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-unattended-security-updates-on-ubuntu)
  * [Enable APT GPG Key Verification on Ubuntu](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-apt-gpg-key-verification-on-ubuntu)
- **[Secure Boot Settings 🔒](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#secure-boot-settings-)**
  * [Set User/Group Owner to Root, and Permissions to Read and Write for Root Only, on `/boot/grub2/grub.cfg`](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-usergroup-owner-to-root-and-permissions-to-read-and-write-for-root-only-on-bootgrub2grubcfg)
  * [Set Boot Loader Password](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-boot-loader-password)
- **[Process Hardening ⚙️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#process-hardening-%EF%B8%8F)**
  * [Restrict Core Dumps](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#restrict-core-dumps)
  * [Enable Randomized Virtual Memory Region Placement](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-randomized-virtual-memory-region-placement)
- **[OS Hardening](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#os-hardening)**
  * [Remove Legacy Services](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#remove-legacy-services)
  * [Remove xinetd/inetd if Not Needed⚙️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#remove-xinetdinetd-if-not-needed%EF%B8%8F)
  * [Disable or Remove Unused Services](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-or-remove-unused-services)
  * [Set Daemon Umask](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-daemon-umask)
- **[User Account Management 👤](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#user-account-management-)**
  * [Limit Administrator Privileges to only Necessary Accounts](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#limit-administrator-privileges-to-only-necessary-accounts)
  * [Setting Up SUDO for User with Only Certain Delegated Privileges](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#setting-up-sudo-for-user-with-only-certain-delegated-privileges)
  * [Check User Home Directory is Accessible by other User or Not](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#check-user-home-directory-is-accessible-by-other-user-or-not)
  * [Enforcing Strong Password Criteria](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enforcing-strong-password-criteria)
  * [Check User Are Using Old Password As new Password or Not](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#check-user-are-using-old-password-as-new-password-or-not)
  * [Set Auto Logout for Inactive Users](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#set-auto-logout-for-inactive-users)
  * [Configure Account Lockout Policy 🔒](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#configure-account-lockout-policy-)
  * [Configure Password Expiry Date](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#configure-password-expiry-date)
  * [Configure Account Expiry Date Of Temporary Account 👤](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#configure-account-expiry-date-of-temporary-account-)
  * [Monitor and Remove Inactive Users](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#monitor-and-remove-inactive-users)
  * [Disable Unused System Accounts](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-unused-system-accounts)
  * [Restrict Use of Empty Passwords](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#restrict-use-of-empty-passwords)
- **[Network Security 🛡️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#network-security-%EF%B8%8F)**
  * [Restrict Service Access to Authorized Users via Firewalls & Controls](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#restrict-service-access-to-authorized-users-via-firewalls--controls)
  * [Disable IP forwarding](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-ip-forwarding)
  * [Disable Send Packet Redirects](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-send-packet-redirects)
  * [Disable Source Routed Packet Acceptance](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-source-routed-packet-acceptance)
  * [Disable ICMP Redirect Acceptance](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-icmp-redirect-acceptance)
  * [Enable Ignore Broadcast Requests](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-ignore-broadcast-requests)
  * [Enable Bad Error Message Protection](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-bad-error-message-protection)
  * [Enable TCP/SYN Cookies](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-tcpsyn-cookies)
  * [Close Unused Open Ports](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#close-unused-open-ports)
  * [Log Suspicious Packets (`log_martians`)](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#log-suspicious-packets-log_martians)
- **[Remote Access and Secure Communication 🤖](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#remote-access-and-secure-communication-)**
  * [Secure SSH](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#secure-ssh)
  * [Use VPNs for Secure Remote Access](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#use-vpns-for-secure-remote-access)
- **[Logging and Monitoring ⚠️](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#logging-and-monitoring-%EF%B8%8F)**
  * [Enable System Auditing](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-system-auditing)
  * [Enable Logging for Critical System Files](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-logging-for-critical-system-files)
  * [Monitor Login Failures](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#monitor-login-failures)
  * [Implement ClamAV For Ubuntu](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#implement-clamav-for-ubuntu)
  * [Scanning for Misconfigurations & Vulnerabilities](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#scanning-for-misconfigurations--vulnerabilities)
- **[Kernel Hardening](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#kernel-hardening)**
  * [Enable and Configure SELinux](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-and-configure-selinux)
  * [Disable IPv6 if Not Needed](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#disable-ipv6-if-not-needed)
  * [Enable Address Space Layout Randomization (`ASLR`)](https://github.com/arijitdirghangi/OS-Hardening/blob/main/Ubuntu_20_04_OS_hardening.md#enable-address-space-layout-randomization-aslr)
- **[Security Awareness and Training 👨🏻‍💻]()**
  * [Security Awareness Training]()
  * [Incident Response Planning]()

