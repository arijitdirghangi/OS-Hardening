### Preparation and Installation 🛡️

#### Protecting a Newly Installed Machine from Network Threats 🪲 <br/>
- When setting up a new system, it is vulnerable to network-based attacks until security configurations are in place. To mitigate this risk, the machine should be isolated from untrusted networks until it is fully installed and hardened.

- We can achive this using `router` or `host based firewall`. <br/>

<br/>

**So i have created vm (`Ubuntu 20.04`) on Hyper-V**
- We can create a separate switch, which isolates vm from our Host machine network.
- Another way, we can install an **Host Based firewall** (ex: UFW) and block all incomming connection, Only allow connection from specific host on spcific port.


**We’re Using Host Based firewall (`UFW`) to isolate our vm :**
- Installing UFW (Uncomplicated Firewall)
    - `apt install ufw -y`

- If we want the VM itself to block incoming/outgoing connections:
```
sudo ufw default deny incoming
sudo ufw default allow outgoing
ufw allow from 192.168.0.118 to any port 22
sudo ufw enable

# 192.168.0.118 is my Host Machine-Ip

#To Check number of these rules are
sudo ufw status numbered
```

  <img src="https://github.com/user-attachments/assets/84a9f6a2-f3bd-4a60-91f2-3f13eda2073e" alt="" width="850px"></a>
  <br>

<br/>

---- 

#### Set a BIOS/Firmware Password 🔒 <br/>
- The BIOS/Firmware is a critical component of a system's security. Without proper protection, an attacker with physical access can modify boot settings, reset passwords, or boot from unauthorized devices to compromise the system. Setting a strong BIOS password helps prevent unauthorized access and security bypasses.

💡 Steps to Implement:

1. Access the BIOS/UEFI Setup Menu
    - Each manufacturer uses different keys to enter BIOS. Try pressing one of the following keys during startup
2. Set a BIOS/UEFI Administrator Password
    - Navigate to the Security or Password section.
    - Look for options such as `Supervisor` Password, Setup Password, or `Admin` Password.
    - Set a strong password and confirm the changes.

  <img src="https://github.com/user-attachments/assets/80432cec-9853-4e63-90fd-cabbf97044a8" alt="" width="650px"></a>
  <br/>

3. After reboot, if we try to enter BIOS it will ask for password

  <img src="https://github.com/user-attachments/assets/13c6c550-7f79-4155-8e2d-598993a2618f" alt="" width="650px"></a>
  <br>

<br/>

---- 

#### Configure The Device Boot Order To Prevent Unauthorized Booting From Alternate Media <br/>
- To prevent unauthorized access and security bypasses, configure the boot order to restrict booting from external media. This stops attackers from using **live USBs** or CDs to bypass OS security controls.


💡 Steps to Implement: <br/>
- Disable Boot from External Media <br/>
- In BIOS settings, go to the Boot or Advanced Boot Options menu. <br/>
- Disable booting from USB, CD/DVD, and PXE (`Network Boot`). <br/>
- Set the Primary Boot Device to the internal hard drive. <br/>
- If possible, enable Secure Boot to prevent unauthorized OS loading. <br/> 

**Note ⚠ :**
- While virtual machines (`VMs`) don't have a traditional BIOS interface like physical machines, you can still set a BIOS password within the VM's firmware settings. This can be achieved by accessing the VM's BIOS or UEFI setup during boot and configuring a password there to prevent any unauthorized changes in boot order.

<br/>

---- 

#### Disable USB Usage
- Disabling USB prevents unauthorized devices from being connected, reducing the risk of malware infection and data theft. This can be done via BIOS/UEFI settings, endpoint security solutions, or manually by blocking USB kernel modules.

💡 Steps to block USB:
- Check BIOS/UEFI settings for USB disable options.
- If using endpoint security, we can block USB from AV Policy.

<br/>

---- 

#### Use the latest version  of Ubuntu  
- Using the latest version of Ubuntu ensures that your system benefits from the latest security patches, bug fixes, and performance improvements. Older versions may lack important security updates and feature enhancements, making them more vulnerable to attacks. 

💡 Steps to Implement:

- Check Current Ubuntu Version:     
   - Run the following command to check your current Ubuntu version: `cat /etc/os-release`
- Update System to Latest Version:
   - Backup critical data before proceeding with the upgrade.
   - Run the following commands to update the system to the latest available version:
```
sudo apt update -y # Update all packages to the latest version
sudo apt upgrade -y # Upgrade system packages
```

<br/>

---- 

#### Lock Physical Console Access 🔐
- Disabling Ctrl+Alt+Del prevents accidental or forced reboots from the physical console, reducing the risk of unauthorized or unintentional system restarts.


💡 Steps for Implementation:
```
systemctl mask ctrl-alt-del.target # Disable Ctrl+Alt+Del reboot
```

  <img src="https://github.com/user-attachments/assets/c9c55832-99a1-43bb-80d0-5d688c1f5976" alt="" width="650px"></a>
  <br>



![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Filesystem Configuration 📁

#### Create a separate partition with the `nodev`, `nosuid`, and `noexec` options set for `/tmp`  <br/>
- Creating a separate partition for `/tmp` with the `nodev`, `nosuid`, and `noexec` options ensures better security by restricting potentially dangerous operations in temporary directories. This can help mitigate the risks associated with untrusted files, as well as prevent certain types of attacks, like privilege escalation and executing malicious code from temporary files.

- `nodev`: Prevents device files from being created in the "/tmp" directory.
- `nosuid`: Prevents the execution of set-user-identifier (SUID) programs in "/tmp".
- `noexec`: Prevents the execution of any binaries from the "/tmp" directory.

💡 Steps to Implement:
- During OS installation i already separated the `/tmp` to another hard-disk, so now we just need to set `nodev`, `nosuid`, and `noexec` on `/tmp` folder.
- There is a entry for `/tmp` directory already exits in `/etc/fstab` file, we need to modify line
  
  <img src="https://github.com/user-attachments/assets/304fbf92-48b2-49a1-84df-7a9ace7fb97c" alt="df command output" width="650px"></a>
  <br>

- Now open `/etc/fstab` file in editor : `nano /etc/fstab`
- Add `nodev,nosuid,noexec` in the following line. 

  <img src="https://github.com/user-attachments/assets/11dbbca8-dc22-493e-8da3-ebce2d1ae065" alt="df command output" width="650px"></a>
  <br>

- After updating `/etc/fstab`, run: `sudo mount -o remount /tmp`
- Verify the mount : `df -h /tmp` && `mount | grep /tmp`

  <img src="https://github.com/user-attachments/assets/3685951f-fe0c-4cee-8c9b-14842f868422" alt="df command output" width="650px"></a>
  <br>

- To ensure the options are applied correctly, check if the partition prevents execution and device files creation:
- Try creating a device file in `/tmp`: `sudo -u <username> mknod /tmp/testdevice c 1 3`
  - It should fail because `nodev` is set

  <img src="https://github.com/user-attachments/assets/54f66453-273d-482b-89f3-2fbdcb10a26c" alt="df command output" width="650px"></a>
  <br>

- Note ⚠️
  - If anyone run this command as `root` user it will `bypass` the restriction, so it's always good practice to lock `root` user account.   

- Try running an executable from `/tmp`: `nano /tmp/check.sh`
```bash
#!/bin/bash
echo LOL

chmod +x /tmp/check.sh
/tmp/check.sh
```

  <img src="https://github.com/user-attachments/assets/0fd8e98b-28cb-43fb-b489-ea64c8f7a530" alt="df command output" width="650px"></a>
  <br>

- It should fail because `noexec` is set.
  - Note ⚠️
    - The `noexec` mount option is applied to `/tmp`, preventing direct execution of files. However, this restriction can be bypassed by explicitly invoking an interpreter, such as: `bash /tmp/check.sh`

  <img src="https://github.com/user-attachments/assets/1b410621-e583-4e8c-8bdd-7f203060006d" alt="df command output" width="650px"></a>
  <br>    
 - To fully mitigate this risk:
 - Use `AppArmor` or `SELinux` to enforce execution restrictions at the system level.

---

`💡 2ND Scenario`
If you haven't separated the partitions during OS installations, now you want to separate `/tmp` to different partition, then follow the below steps:

- List your all available disks using: `fdisk -l`

  <img src="https://github.com/user-attachments/assets/42180ee9-0b35-44ec-8541-723452999b28" alt="df command output" width="650px"></a>
  <br>  

- Create a new partition for `/tmp` using fdisk: `sudo fdisk /dev/sda` `#Replace with your disk name`
  - Press `n` to create a new partition.
  - Choose a partition number (e.g., 2).
  - When asked for the start sector, press `Enter` to use the default (next available).
  - When asked for the end sector, specify how much space you want (e.g., +13G for a 13 GiB /tmp).
  - Press `w` to save and exit.

  <img src="https://github.com/user-attachments/assets/de0b0f79-b6a4-4774-a636-ff479299d655" alt="" width="650px"></a>
  <br>  

  <img src="https://github.com/user-attachments/assets/a85a35f3-5afa-4713-b924-e49ebe28a3cf" alt="" width="650px"></a>
  <br>

- Format the New Partition:
  - Format the new partition with a file system (e.g., ext4): `sudo mkfs.ext4 /dev/sdaX` `(Replace X with your partition)`

  <img src="https://github.com/user-attachments/assets/6bb4977b-5e7e-4935-923e-342c4985c182" alt="" width="650px"></a>
  <br>

- Mount the New Partition with Security
  - Ensure `/tmp` is empty before mounting
    - It’s best to clear `/tmp` on `reboot` (this is common practice).
  - Backup current /tmp (just in case):
    - `sudo cp -a /tmp /tmp_backup`

  - Create a mount point and mount the partition: `sudo mount /dev/sdaX /tmp` `(Replace X with your partition)`
  - Add the following entry to `/etc/fstab` to ensure the partition is mounted on reboot:
    - `/dev/sda2    /tmp    ext4    nodev,nosuid,noexec    0    2` `(Replace /dev/sda2 with your partition)`

  <img src="https://github.com/user-attachments/assets/387f5b83-b101-4b7e-b965-2d82c7c02de3" alt="" width="650px"></a>
  <br>

- After updating `/etc/fstab`, run: `mount -a` & `sudo mount -o remount /tmp`
- Verify the mount : `df -h /tmp` && `mount | grep /tmp`

  <img src="https://github.com/user-attachments/assets/7d0fc9f8-20b1-46e7-ada0-21880a35026c" alt="" width="650px"></a>
  <br>

- Testing the security settings is same, as i mention above.😊


![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

#### Create separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home` <br/>
- Creating separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home` provides better isolation, security, and management of system resources. These partitions allow for independent management, such as setting appropriate mount options and file system types, which can help protect sensitive data, ensure log retention, and optimize performance. It also prevents one partition from filling up and impacting others.


💡 Steps to Implement:

`1ST Scenario:` Create Seprarate partition during OS Installations 💡 <br/>
- I have taken two hard-disk one for os installation and another for storing specific directory content.
  - 20GB Hard-disk OS Installation.
  - 70GB Hard-disk for storing specific directory content. 

- In my case i already created separated the partition `/var`, `/var/log`, `/var/log/audit`, and `/home` into `70GB` hard-disk. <br/>
- `fdisk -l`- output:

  <img src="https://github.com/user-attachments/assets/ed54c9fa-13a2-44f0-9412-27e453ffde2f" alt="fdisk command output" width="650px"></a>
  <br>

- `df -h` command output

  <img src="https://github.com/user-attachments/assets/ab7efbbb-67fc-4b52-acdd-3000318fa69e" alt="fdisk command output" width="650px"></a>
  <br>

`2ND Scenario:` After OS installation manually  partitioned the disk and moved directories like `/home`, `/var`, etc. to separate partitions.





![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)


