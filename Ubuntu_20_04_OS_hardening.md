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

**💡 Steps to Implement:**

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


**💡 Steps to Implement:** <br/>
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

**💡 Steps to block USB:**
- Check BIOS/UEFI settings for USB disable options.
- If using endpoint security, we can block USB from AV Policy.

<br/>

---- 

#### Use the latest version  of Ubuntu  
- Using the latest version of Ubuntu ensures that your system benefits from the latest security patches, bug fixes, and performance improvements. Older versions may lack important security updates and feature enhancements, making them more vulnerable to attacks. 

**💡 Steps to Implement:**

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


**💡 Steps for Implementation:**
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

**💡 Steps to Implement:**
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

**`💡 2ND Scenario`**
If you didn’t separate the `/tmp` partition during OS installation and wish to do so now, follow the steps below.

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


<br/>

---- 

#### Create separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home` <br/>
- Creating separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home` provides better isolation, security, and management of system resources. These partitions allow for independent management, such as setting appropriate mount options and file system types, which can help protect sensitive data, ensure log retention, and optimize performance. It also prevents one partition from filling up and impacting others.


**💡 Steps to Implement:**

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

---

**`💡 2ND Scenario:`** 
In case you didn’t set up separate partitions during installation and want to do it now, you can manually configure it using these steps.

<br/>

**💡 Steps to Implement:**

**Identify Available Disks:**
 - Use `sudo fdisk -l` to list available disks.

<br/>

**Create Partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home`:**
- Use fdisk or parted to create partitions for each directory.

<br/>

**Format Each Partition:**
- Format partitions with the ext4 file system:
```
sudo mkfs.ext4 /dev/sda1 (replace /dev/sda1 with your partition name)
```

<br/>

**Create temporary mount points & copy existing logs**
```bash
sudo mkdir -p /mnt/var /mnt/var_log /mnt/var_log_audit /mnt/home
sudo mount /dev/sdaw /mnt/var
sudo mount /dev/sdaX /mnt/var_log
sudo mount /dev/sdaY /mnt/var_log_audit
sudo mount /dev/sdaZ /mnt/home

sudo rsync -aAXv /var/ /mnt/var/
sudo rsync -aAXv /var/log/ /mnt/var_log/
sudo rsync -aAXv /var/log/audit/ /mnt/var_log_audit/
sudo rsync -aAXv /home/arijit /mnt/home/  # Copy only the user directory (not the entire /home folder itself)

#If you want to move all users under /home, just do:
sudo rsync -aAXv /home/ /mnt/home/
```
> Note ⚠ : The trailing slashes means not the home dir but the content of home directory.

  <img src="https://github.com/user-attachments/assets/c84855af-17eb-4891-bd79-2b3b12d4f709" alt="fdisk command output" width="650px"></a>
  <br>

  <img src="https://github.com/user-attachments/assets/a84e8851-9fca-4320-88e0-0825d15c5e93" alt="fdisk command output" width="650px"></a>
  <br>

> In the picture above, I made a mistake by using `rsync -av /home`, which results in copying the entire `/home` directory into `/mnt/home`, leading to a nested path like `/mnt/home/home/<username>`.  
>  
> To avoid this, use trailing slashes to copy only the contents of `/home`, like so:  
> `sudo rsync -aAXv /home/ /mnt/home/`  
>  
> Alternatively, if you want to copy a specific user's home directory, use:  
> `sudo rsync -aAXv /home/arijit /mnt/home/`



<br/>

**Update `/etc/fstab` to Persist Mounts:**
 - Add these entries to `/etc/fstab`:
```
/dev/sda1    /var    ext4    defaults    0    2
/dev/sda2    /var/log    ext4    defaults    0    2
/dev/sda3    /var/log/audit    ext4    defaults    0    2
/dev/sda4    /home    ext4    defaults    0    2
```

<br/>

**Verify the Mounts:**
- After updating `/etc/fstab`, mount the partitions: `sudo mount -a`
- Verify by running: `mount | grep /var` OR `df -h`

  <img src="https://github.com/user-attachments/assets/ef8bf710-55d8-477e-98c4-dbd0843ce5dc" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> **Note ⚠ : If it's shows like these:** 
```
root@arijit:~# mount -a
mount: /var/log/audit: mount point does not exist.
```
> It’s show because "audit" not exits under "/var/log/", So we have to create one:
```
root@arijit:~# mkdir -p /var/log/audit/

#Now RUN again 
mount -a
```

<br/>



---- 

#### Bind mount /var/tmp to /tmp <br/>
- Bind mounting `/var/tmp` to `/tmp` is a security and system management practice used to ensure that the contents of /tmp are stored on a separate partition (in this case, /var/tmp) while still using the same path for access.

**Why Do This?**
- Security: By separating `/tmp` from the root filesystem, you can apply more restrictive mount options (e.g., noexec, nosuid) to "/tmp", improving security.
- Disk Space Management: If `/var` has more disk space, it allows /tmp to grow without affecting the root partition.


**✅ When Should You Use Bind Mount `/tmp` → `/var/tmp`?**

Use this setup if:
- You do not have a separate partition for `/tmp`.
- You want to enforce strict security on both `/tmp` and `/var/tmp` (like `noexec, nosuid, nodev`).
- You want to ensure both dirs share the same storage (usually to prevent `/var` from filling up due to temp files).
- You don’t need persistent temp files between reboots (`/tmp` gets cleared, `/var/tmp` won't anymore).

> Example use case: Minimalist installations or containers where conserving space and reducing partitions is more important than strict separation of temp storage behavior.

<br/>

**❌ When Should You Avoid This Setup?**

Avoid bind mount if:
- You've already separated `/tmp` and `/var` to their own partitions.
- You rely on persistent files in `/var/tmp` that should survive across reboots.
- You want to apply different mount options (like `noexec` on `/tmp` but allow execution in `/var/tmp`).
- You care about clear separation of temp file lifetimes for compliance or debugging purposes.
> Bind mounts inherit the mount options of the target. You can’t set different options for /var/tmp if it’s a bind mount of /tmp.

<br/>

**🔒 Security Tips**

If you want to apply nodev,nosuid,noexec to both `/tmp` and `/var/tmp`, but keep them separate, the best approach is to:
- Create a dedicated partition for `/var/tmp`.
- Mount it separately in `/etc/fstab`.
- Apply your desired security options there.

<br/>

**💡 Steps to Bind Mount `/var/tmp` to `/tmp`:**
- Make sure the  `/var/tmp` directory exists. If it doesn’t, create it: `sudo mkdir -p /var/tmp`.
 
- Modify `/etc/fstab` to Bind Mount:
    - Edit the `/etc/fstab` file to add a bind mount entry. This ensures that the system will automatically bind mount  `/var/tmp` to `/tmp` on boot: sudo nano /etc/fstab
    - Add the following line at the end of the file: `/var/tmp   /tmp    none    bind,noexec,nosuid,nodev    0   0`
    - This line tells the system to bind mount  `/var/tmp` to `/tmp` every time the system boots.

- Apply the Bind Mount Immediately:
    - To immediately apply the changes without rebooting, run: `sudo mount --bind /var/tmp /tmp`

- Verify the Bind Mount:
    - After applying the changes, verify that the bind mount is working by checking the mount points: `mount | grep /tmp`
    - Try writing files to `/tmp` and confirm that they are stored under  `/var/tmp` by checking the disk usage with `ls /var/tmp`.

🔗 Reference:

- https://superuser.com/questions/306407/why-bind-mount-var-tmp-to-tmp
- https://www.tenable.com/audits/items/CIS_Debian_Linux_7_v1.0.0_L1.audit:46439183a92a2f2d0ff272893ca0504b


<br/>

---- 

#### Set `nodev` option to /home
- The `nodev` option is used to prevent the mounting of device files in a specific directory. By setting the nodev option on /home, you ensure that no device files (e.g., block or character devices) can be created or accessed within the /home directory. This enhances security by preventing attackers from creating or using device files in user directories.

**💡 Steps to Set nodev Option on `/home`:**
- Modify `/etc/fstab`:
    - Edit the `/etc/fstab` file to include the nodev option for the `/home` partition.
    - `sudo nano /etc/fstab`

- We already have separated partitions for `/home`, find the corresponding line and add the `nodev` option. For example:
- `/dev/sda2    /home    ext4    defaults,nodev    0   2`  

  <img src="https://github.com/user-attachments/assets/94b581b4-f127-4fe0-b0e4-cf2c2fecec60" alt="fdisk command output" width="650px"></a>
  <br>

- After updating `/etc/fstab`, run: `sudo mount -o remount /home`

  <img src="https://github.com/user-attachments/assets/da5a04dc-fb3e-4102-9f3d-a398d34ca0cc" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---- 

#### Set nodev, nosuid, and noexec options on /dev/shm

The /dev/shm directory is a temporary file storage location in memory (shared memory). It is used for applications that need fast temporary storage in RAM. However, because it resides in memory, it could be a target for various attacks, especially if applications running on the system use it insecurely. To enhance security, it is essential to set the nodev, nosuid, and noexec options on /dev/shm.

- nodev: Prevents the creation of device files in /dev/shm, mitigating risks of device file exploitation.
- nosuid: Prevents the setuid and setgid bits from taking effect, reducing the risk of privilege escalation through shared memory.
- noexec: Prevents the execution of binaries in /dev/shm, protecting against malicious code that might be placed in the shared memory.

**Why Set These Options?**

Security: Protects against attacks like privilege escalation, code execution, and device file creation within shared memory.
Integrity: Ensures that no untrusted binaries are executed from the memory-backed /dev/shm directory.
Control: Gives administrators control over what can and cannot be done in /dev/shm.


**💡 Steps to Set `nodev`, `nosuid`, and `noexec` on `/dev/shm`:**

- Modify `/etc/fstab` to Include the Options:
    - Open the `/etc/fstab` file for editing: `sudo nano /etc/fstab`
    - Add or modify the entry for /dev/shm to include the `nodev`, `nosuid`, and `noexec` options. For example:
      
    - `tmpfs     /dev/shm    tmpfs   defaults,nodev,nosuid,noexec   0   0`

  <img src="https://github.com/user-attachments/assets/6dfc3ce3-ee4b-4c3e-bd65-6bc57c786f76" alt="fdisk command output" width="650px"></a>
  <br>

- This line ensures that these security options are applied to the /dev/shm mount point.
- After updating `/etc/fstab`, run: `sudo mount -o remount /dev/shm`

  <img src="https://github.com/user-attachments/assets/9bef4c1a-ccbb-4627-bcc3-214ee3ed6fa1" alt="fdisk command output" width="650px"></a>
  <br>

Verification:
- Check for Device Creation: Try creating a device file in /dev/shm to see if the nodev option is working. It should fail with a permission error.
```
sudo mknod /dev/shm/testdev c 7 0
```
- This should fail if `nodev` is properly set.

- Check for Executable Files: Attempt to execute a file in /dev/shm to see if the noexec option is working.
```
sudo touch /dev/shm/testscript
sudo chmod +x /dev/shm/testscript
/dev/shm/testscript
```
- The file should not execute if `noexec` is set correctly.

> 💡 By setting the nodev, nosuid, and noexec options on /dev/shm, you significantly reduce the attack surface of the system, preventing unauthorized device file creation, privilege escalation, and executable code execution in the shared memory space.

<br/>

---- 

#### Set sticky bit on all world-writable directories

- The sticky bit is a permission that can be set on directories to restrict the deletion of files within the directory. When the sticky bit is set, only the file owner, the directory owner, or the root user can delete or rename files within that directory, even if others have write permissions to the directory. This is especially useful for directories like /tmp, where multiple users can write files but shouldn't be able to delete or modify other users' files.

Setting the sticky bit on world-writable directories enhances security by preventing users from accidentally or maliciously deleting or renaming files owned by other users.


**Why Set the Sticky Bit?**

- Prevent Unauthorized File Deletion: Ensures that only the file owner, directory owner, or root user can delete or rename files, even in world-writable directories.
- Improves Security in Shared Directories: Protects sensitive files in shared directories, such as /tmp or /var/tmp.

<br/>

**Find World-Writable Directories:**
- Use the following command to list all directories that are world-writable (`777` permissions or `rwxrwxrwx`):
```
find / -type d -perm -0002 -exec ls -ld {} \; 2> /dev/null
```
- This will search for all directories with world-writable permissions.

  <img src="https://github.com/user-attachments/assets/6820b047-c9bf-4356-8dc2-30035b77e65e" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**To Set Sticky Bit:**
 - Use the `chmod` command to set the sticky bit on each world-writable directory:
 ```
sudo chmod +t <directory_path>
```

<br/>

**💡 Automate the process:**
- To apply the sticky bit on all world-writable directories, use a loop:
```
find / -type d -perm -0002 -exec sudo chmod +t {} \; 2> /dev/null
```

  <img src="https://github.com/user-attachments/assets/782b3a5a-0c23-46f5-81a9-af3e2f3469f7" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---- 

#### Enable Hard/Soft Link Protection
- Attackers may exploit insecure hard links and symlinks to access sensitive files or escalate privileges. Enabling protection prevents these attacks by restricting how links can be used.

<br/>


**💡 Steps to configures:**
- Enable Hard and Symlink Protection  
 - Create or modify the system configuration file:  
```
echo "fs.protected_hardlinks = 1" | sudo tee -a /etc/sysctl.conf  
echo "fs.protected_symlinks = 1" | sudo tee -a /etc/sysctl.conf  
```

<br/>

- Apply changes immediately:  
```
sudo sysctl -p /etc/sysctl.conf  
```

<br/>

- Verify settings:  
```shell
sysctl fs.protected_hardlinks  
sysctl fs.protected_symlinks
#Expected Output: Both should return 1 (enabled).   
```

  <img src="https://github.com/user-attachments/assets/35804ebe-4ec8-4d3f-a64f-8ebc3feb83ae" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**💡 Understanding the Settings :**  
- 'fs.protected_hardlinks = 1'  
  - Prevents unprivileged users from creating hard links to files they do not own.  
- 'fs.protected_symlinks = 1'  
  - Blocks symlink-based privilege escalation attacks by preventing symlink access to files users don’t own.  

<br/>

🔗 Reference:  
- https://sysctl-explorer.net/fs/protected_symlinks/

<br/>

---- 

#### Disable Uncommon Filesystems

Disabling unused or uncommon filesystems reduces the attack surface and prevents unauthorized mounting of potentially insecure storage formats.


<br/>

**💡 Steps to configure:**
1. Block Uncommon Filesystems  <br/>
i) Blacklist the filesystems in `/etc/modprobe.d/blacklist.conf`:  
```
sudo tee -a /etc/modprobe.d/blacklist.conf <<EOF
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf
blacklist fat
blacklist vfat
blacklist nfs
blacklist nfsv3
blacklist gfs2
EOF
```
- This ensures they are not automatically loaded on boot.

<br/>

2. Apply Changes Immediately  
- Rebuild the initramfs (important for persistence): sudo update-initramfs -u 
- Unload any currently loaded uncommon filesystem modules:  
```
sudo rmmod cramfs freevxfs jffs2 hfs hfsplus squashfs udf fat vfat nfs nfsv3 gfs2 2>/dev/null
```

- Verify the settings:  
```
lsmod | grep -E 'cramfs|freevxfs|jffs2|hfs|hfsplus|squashfs|udf|fat|vfat|nfs|nfsv3|gfs2'
```

  <img src="https://github.com/user-attachments/assets/8994f8d3-cd76-4f4e-95a6-b00cc63cbe28" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

💡   Understanding the Settings  
- `install <module> /bin/false`  
    - Prevents the filesystem from being loaded as a kernel module.  
- `blacklist <module>`      
    - Stops the kernel from automatically loading these filesystems.  
- `update-initramfs -u`  
    - Ensures changes are applied in the boot process.  

<br/>

---- 

#### Lock The Boot Directory 
- The /boot directory contains critical bootloader files, such as the kernel and GRUB configurations. If an attacker modifies these files, they can gain persistent access or bypass security measures. Locking the /boot directory prevents unauthorized modifications.

<br/>


**💡 Steps to Lock the Boot Directory :** 

**Set Boot Directory as Read-Only**  
- Modify `/etc/fstab` to prevent accidental modifications: `sudo nano /etc/fstab` 
- Add the following line (or modify the existing '/boot' entry):  
```
UUID=<BOOT_PARTITION_UUID> /boot ext4 defaults,ro 0 1

OR
    
LABEL=/boot /boot ext4 defaults,ro 0 1
```

  <img src="https://github.com/user-attachments/assets/8f086b35-e583-4d77-8411-fa5b64444d61" alt="fdisk command output" width="650px"></a>
  <br>

- Replace '<BOOT_PARTITION_UUID>' with the actual UUID of the boot partition (find it using 'blkid').  
- 'ro' sets the directory as read-only.  

<br/>

**Restrict File Permissions**  
- Ensure only root can modify boot files:
```
sudo chown -R root:root /boot
sudo chmod -R 700 /boot
```

  <img src="https://github.com/user-attachments/assets/04c8f47f-bd75-4b6a-802d-a48b06404e4e" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### System Updates 🛡️ 


#### **Enable Unattended Security Updates on Ubuntu**
    - Ubuntu systems can automatically receive security patches using the unattended-upgrades package. This ensures that critical vulnerabilities are patched promptly without manual intervention.


<br/>


**💡 Steps to Apply and Automate Security Updates:**

**Install Unattended Upgrades (if not already installed):**
```
sudo apt update
sudo apt install unattended-upgrades
```

<br/>

**Enable Unattended Upgrades:**
- Run the command to enable automatic updates:
```
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

  <img src="https://github.com/user-attachments/assets/65a9918b-94b5-48d8-b185-7d57cfa56d78" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Configuration File (optional):**
- We can customize the behavior in: `/etc/apt/apt.conf.d/50unattended-upgrades`
- Ensure this line is uncommented to apply security updates:
```
"${distro_id}:${distro_codename}-security";
```

  <img src="https://github.com/user-attachments/assets/f388f5c3-fd2c-40c1-bf24-9fa038b52b3c" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Test it works:**
- You can simulate an unattended upgrade:
```
sudo unattended-upgrade --dry-run --debug
```

<br/>

**Manual Security Updates (if needed):**
- To list only security updates manually:
- To apply them:
```
sudo apt list --upgradable | grep security
sudo apt upgrade
```

<br/>

---- 

#### **Enable APT GPG Key Verification on Ubuntu**
- APT uses GPG keys to verify that packages are signed and trusted. This check ensures that your system installs only verified software from trusted sources.


<br/>

**💡 Steps to Manage APT GPG Keys and Enable Verification:**

**Check Installed GPG Keys:(Note: Newer versions of Ubuntu may use /etc/apt/trusted.gpg.d/ instead of apt-key.)**
```
apt-key list
```

<br/>

**Verify Signature Checking Is Enabled:**
- APT checks GPG signatures automatically. If a key is missing or mismatched, APT will show a warning or error before allowing an install.

<br/>

**Import a Trusted GPG Key (if needed):**
- For third-party repositories, you might need to import a GPG key:
```
curl -fsSL <https://example.com/repo.gpg> | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/example.gpg
```

<br/>

**Enable GPG Checks in Repository Configs:**
- Repository definitions in `/etc/apt/sources.list` or `/etc/apt/sources.list.d/*`.list can include the signed-by field to specify the GPG key.


<br/>

>**Note ⚠️**

> If we are just using official **Ubuntu repositories**, we don’t need to change anything. They already: <br/>
> - Sign all packages with official Ubuntu GPG keys.<br/>
> - Use trusted keys stored in **/etc/apt/trusted.gpg.d/**

  <img src="https://github.com/user-attachments/assets/971fe8c0-756e-497e-9408-428d1001ec28" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Enable GPG Checks for Repositories:**
- Ubuntu uses GPG keys to verify packages from trusted repositories.

<br/>

**Default Setup:**
- Ubuntu stores trusted keys in `/etc/apt/trusted.gpg.d/`
- These keys validate official repositories listed in `/etc/apt/sources.list`

<br/>

**Hardening Practice (For Custom Repositories):**
- Modern best practice is to use the `signed-by=` field in APT sources to limit a specific GPG key to a specific repository.
- This improves security by preventing one compromised key from validating all repositories.

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Secure Boot Settings 🔒

#### **Set User/Group Owner to Root, and Permissions to Read and Write for Root Only, on `/boot/grub2/grub.cfg`**
- The `/boot/grub2/grub.cfg` file contains critical bootloader configuration settings. If non-root users have access to this file, they could potentially alter boot parameters, which could compromise the security of the system. It's essential to set the file permissions so that only the root user can read and modify the file.


<br/>

**💡 Steps to Set User/Group Ownership and Permissions for "/boot/grub2/grub.cfg":**

<br/>

**Change Ownership to Root:**
- First, ensure that the owner and group of the 'grub.cfg' file are set to 'root'. Use the 'chown' command to set the ownership:
```
sudo chown root:root /boot/grub2/grub.cfg
chown root:root /etc/grub.conf
chown -R root:root /etc/grub.d
chmod -R og-rwx /etc/grub.d
chmod og-rwx /etc/grub.conf
```

<br/>

**Set Permissions to Read and Write for Root Only:**
- Next, modify the file permissions so that only the root user has read and write access. All other users should have no access to the file.
- You can use the 'chmod' command to set the correct permissions:
`sudo chmod 600 /boot/grub2/grub.cfg`

- This sets the file permissions to `rw-------`, where:
  - The owner (root) has read and write permissions (`rw-`).
  - The group and others have no permissions (`---`).

  <img src="https://github.com/user-attachments/assets/2eececd6-46e1-47e9-9af9-ebcb9eae8965" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---- 

#### **Set Boot Loader Password**
- Setting a bootloader password adds an additional layer of security by preventing unauthorized users from modifying the boot parameters at startup. This is particularly important because attackers with access to the bootloader can modify boot settings, potentially gaining access to the system or altering system behavior. By requiring a password to modify bootloader settings, you can protect the integrity of the boot process.

<br/>

**💡 Steps to Set Boot Loader Password:**

**Generate a GRUB Password Hash:** 
- To set a password for the bootloader, you need to generate a password using the `grub-mkpasswd-pbkdf2` command.
- Run the following command and provide a password when prompted: `grub-mkpasswd-pbkdf2`
- You will receive an output like this:
```
Enter password:
Confirm password:
```
- Copy the PBKDF2 hash and Open this file in editor `/etc/grub.d/00_header`
- Add the follwoing entries
```
cat <<EOF
set superuser="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.96C2A427209BEA03F954265E7D8E5C87AEAB7C5BEBEA0E65496FE7D1072FFAAF2467C70CD639390286E52CAA385364C8BD4747F7FF4654F5DF85B1A4E1D165C1.0D61D7706A7BD9DDD5A23BE15E7BAB054CB98DB5091DD8D233A1D587FFBC6F54E626A8D7DC280619C75D4B2E3E604701D785DF595721398F56D434DE4800DEC8
EOF
```

<br/>

**Update the `grub` configuration:**  `sudo update-grub`

  <img src="https://github.com/user-attachments/assets/4a909a18-7130-4347-a338-96aa7c13008d" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Reboot the system:** 
- In boot menu press `E`.
- It will ask for username (default "root") & type password.

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### **Process Hardening ⚙️**

#### **Restrict Core Dumps**
- Core dumps contain memory snapshots of crashed processes and may expose sensitive information, such as passwords and encryption keys. Restricting core dumps enhances security and prevents unauthorized access to critical data.

<br/>

**💡 Steps to Implement:**

**Disable Core Dumps for All Users:**
- Add the following line to `/etc/security/limits.conf` to disable core dumps : 
    - `* hard core 0`
    - `* soft core 0`

  <img src="https://github.com/user-attachments/assets/b272ecd3-928b-488a-a819-d9b327d1ea61" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Disable Core Dumps via sysctl**
- Modify `/etc/sysctl.d/99-sysctl.conf` OR `/etc/sysctl.conf` to prevent core dumps: 
```
fs.suid_dumpable = 0
kernel.core_pattern=|/bin/false
```
- Apply the changes: `sudo sysctl -p /etc/sysctl.d/99-sysctl.conf`

  <img src="https://github.com/user-attachments/assets/aff29379-dd03-46d1-bef3-79727da8d25f" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Disable Core Dumps for Systemd Services**
- Edit `/etc/systemd/system.conf` and `/etc/systemd/user.conf` to include: DumpCore=no
- Reload systemd configurations: `sudo systemctl daemon-reexec`

  <img src="https://github.com/user-attachments/assets/560ae6ac-b824-40b8-8b4d-918e67f75ae6" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**🛠️ Verification:**
- Run the following command to check the core dump configuration: `ulimit -c`

  <img src="https://github.com/user-attachments/assets/c9e5ebbc-bcae-4cd1-b946-9c3c40c27d51" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---- 

#### **Enable Randomized Virtual Memory Region Placement**
- Address Space Layout Randomization (ASLR) randomizes memory addresses to make it harder for attackers to predict memory locations, mitigating buffer overflow and memory corruption attacks.

<br/>

**💡 Steps to Implement:**

**Enable ASLR via `sysctl`**
- Add the following line to `/etc/sysctl.conf` to ensure ASLR is enabled: `kernel.randomize_va_space = 2`
- Apply the changes: `sudo sysctl -p`


**Verify ASLR Status:**
- Check if ASLR is enabled by running: cat /proc/sys/kernel/randomize_va_space
- Expected Output:
```
 - 2 → Full ASLR enabled ✅
 - 1 → Partial ASLR enabled ⚠️
 - 0 → ASLR disabled ❌ (Needs fixing)
```
- After reboot, run: `cat /proc/sys/kernel/randomize_va_space`
- It should return `2`, confirming that ASLR is fully enabled.


**(Optional) Protect ASLR Setting**
- Prevent unauthorized modifications by making the `sysctl` setting immutable:
`sudo chattr +i /etc/sysctl.conf`


**🛠️ Verification:**
After reboot, run: `cat /proc/sys/kernel/randomize_va_space`
It should return `2`, confirming that ASLR is fully enabled.


  <img src="https://github.com/user-attachments/assets/a5f70fc0-a08a-4e02-8b23-5d05de7e5c4a" alt="fdisk command output" width="650px"></a>
  <br>


![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### **OS Hardening**

#### **Remove Legacy Services**
- Legacy services like Telnet, rsh, rlogin, rcp, ypserv, ypbind, tftp, talk are considered insecure because they transmit credentials and data in plaintext. Removing them reduces attack surface and prevents accidental use.

<br/>

**💡 Steps to Implement:**

**Check if Legacy Packages Are Installed**
```
dpkg -l | grep -E 'telnet|rsh|rlogin|rcp|ypbind|ypserv|tftp|talk'
```

<br/>

**Remove Insecure Legacy Services**
```
sudo apt remove --purge -y telnetd rsh-client rsh-server rlogin rsh-redone-client tftp tftpd talk talkd nis

# used the package name listed using "dpkg" command
sudo apt remove --purge -y telnet
```
> Note: Some packages may not be installed by default. apt will just skip them.


###### **Disable Remaining Services (if installed manually or still running)**

**Check for active legacy services:**
```
sudo systemctl list-units --type=service | grep -E 'telnet|rsh|tftp|talk|yp'
```

<br/>

**Stop and disable any leftover ones:** `sudo systemctl disable --now <service_name>`
<br/>

**Verify any remaing service:** `dpkg -l | grep -E 'telnet|rsh|rlogin|rcp|ypbind|ypserv|tftp|talk'`

<br/>

---- 

#### **Remove xinetd/inetd if Not Needed⚙️**
- If you confirmed they are not required, removing them entirely:
    - Reduces the attack surface.
    - Eliminates any risk of them being enabled later by mistake or due to package updates.

<br/>


**💡 Steps to Remove:**

<br/>

**Check if Installed:** `dpkg -l | grep -E 'xinetd|inetutils-inetd'` <br/>

**Stop the Service (if running):** `sudo systemctl disable --now xinetd` <br/>

**Remove the Packages:** `sudo apt remove --purge -y xinetd inetutils-inetd`

<br/>

**🛠️ Verification:** `dpkg -l | grep -E 'xinetd|inetutils-inetd'`
 - Should return no output if successfully removed.


<br/>

---- 

#### **Disable or Remove Unused Services**
- Disabling or removing unnecessary services on a server is crucial for security. Services such as FTP, DNS, LDAP, SMB, DHCP, NFS, and SNMP can expose the system to potential attacks. By disabling or removing these services, you reduce the number of open ports and limit the attack surface of the system.

<br/>

**💡 Steps to Disable or Remove Unused Services:**

**List active services:**
    - First, check which services are currently active on your system:
```
sudo systemctl list-units --type=service --state=running
```

  <img src="https://github.com/user-attachments/assets/5108f511-0d40-45dd-8e06-08ee3d30f329" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Disable/Remove unwanted services:**
- If you find any unwanted services, disable them to prevent them from starting automatically on boot. For example:
- If you are sure you will not need these services, you can remove the corresponding packages. For example:

**Example: SMB (Samba)** 
```
sudo systemctl stop smb
sudo systemctl disable smb
```
  <img src="https://github.com/user-attachments/assets/f7110e3a-2449-4137-b4cf-100d079a14e4" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---- 

#### **Set Daemon Umask**
- For each daemon, you can define a default umask. Typically, this can be set in the service's startup script or configuration files, e.g., `/etc/init.d/<service>` or `/etc/systemd/system/<service>.service`.

<br/>

**💡 Steps to configure:**
**Edit the Daemon Configuration:**
- For each daemon, you can define a default umask. Typically, this can be set in the service's startup script or configuration files, e.g., /etc/init.d/<service> or /etc/systemd/system/<service>.service.

<br/>

**Set the Umask in the Script:**
- Add the following line in the service startup script or configuration:
- This ensures that files created by the daemon are created with restrictive permissions.
```
umask 0077 # OR
umask 0027
```
- After change restart the service: `sudo systemctl restart ssh`

  <img src="https://github.com/user-attachments/assets/0dddda1a-9a8e-4dab-9740-79b11d6a22b2" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**Test the Daemon:**
- Ensure that the daemon is running with the desired umask and that files it creates have the correct permissions.

> By enforcing a strict umask on daemons, you can enhance system security by ensuring that files and directories created by the system are not overly permissive.

<br/>

**Override umask for a service:**
```
sudo systemctl edit nginx

#Then add
[Service]
UMask=027

#Save and exit, then:
sudo systemctl daemon-reload
sudo systemctl restart nginx
```


![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### **User Account Management 👤**


#### **Limit Administrator Privileges to only Necessary Accounts**
- Restrict administrative privileges to only essential accounts based on the Principle of Least Privilege (PoLP). This reduces the risk of unauthorized access, accidental misconfiguration, and privilege escalation attacks. Regularly audit and remove unnecessary administrative access.

<br/>

**💡 Steps to configure:**
1. Use sudo instead of root for administrative tasks.
2. Restrict sudo access using `/etc/sudoers` (e.g., visudo).
3. Audit user accounts with getent passwd and check for unnecessary admin privileges.
4. Limit access to privileged commands via sudo rules.

<br/>

**Verification Method:**
- Run **sudo -l -U <user>** to verify a user's sudo privileges.
- Check `/etc/passwd` and `/etc/group` to ensure only necessary accounts have administrative access.

<br/>

---- 

#### **Setting Up SUDO for User with Only Certain Delegated Privileges**
- Configure sudo to grant users specific administrative privileges while minimizing security risks. Instead of giving full root access, allow users to execute only necessary commands.

###### **Example:**
```
thor ALL=(ALL) ALL # → Full sudo access
loki ALL=(ALL) /usr/bin/systemctl status sshd # → Can only check SSHD service status
hulk ALL=(ALL) STORAGE # → Can access the STORAGE command
```

**💡 Best Practices:**
- Use visudo to edit `/etc/sudoers` or create rule-specific files in `/etc/sudoers.d/`.
- Avoid modifying `/etc/sudoer`s directly to prevent syntax errors.
- Verification: Use visudo to review entries and `sudo -l -U <username>` to list allowed commands.

<br/>

---- 

#### **Check User Home Directory is Accessible by other User or Not**
- Ensure that user home directories are not accessible by unauthorized users. By default, home directories should have **700** or **750** permissions to prevent other users from accessing them.


<br/>

###### **Run the following command to check home directory permissions:** 
```
ls -la /home/
```

###### **Default Permissions in Different Distributions:**
> Ubuntu: The useradd utility creates home directories with 755 permissions, making them accessible to other users.

<br/>

**💡Steps to Secure Home Directory Permissions:**

###### **Modify the UMASK value in /etc/login.defs:**
- Change UMASK to `077` to ensure new users have `700` permissions by default.
- This ensures only the owner has full access, and others have no access.

  <img src="https://github.com/user-attachments/assets/660ebf47-234b-49b7-b9cf-5771d9948b75" alt="fdisk command output" width="650px"></a>
  <br>

###### **💡 Manually update permissions for existing users (if needed):**
> RUN the following command: chmod 700 /home/*


----

#### **Enforcing Strong Password Criteria**
- Ensure that users set strong passwords to enhance system security. Implement policies that enforce complexity, length, expiration, and history to prevent weak or reused passwords.

<br/>

**💡 Steps to Configure Password Policy using `pwquality.conf`:**

Install “libpam-pwquality”
```
apt install libpam-pwquality -y
```

###### **Locate the Configuration File**
 - The pwquality.conf file is usually found at: /etc/security/pwquality.conf

###### **Modify Password Policy Settings, open the file in a text editor (e.g., nano or vim):**
```
sudo nano /etc/security/pwquality.conf
```

###### **Add or modify the following parameters:**
| Parameter | Description |
|-----------|------------|
| minlen=12 | Minimum password length (e.g., 12 characters) |
| dcredit=-1 | Requires at least one digit |
| ucredit=-1 | Requires at least one uppercase letter |
| lcredit=-1 | Requires at least one lowercase letter |
| ocredit=-1 | Requires at least one special character |
| retry=3 | Number of retries before rejection |
| dictcheck=1 | Prevents dictionary words in passwords |
| usercheck=1 | Prevents username in passwords |
| enforcing=1 | Enforcing PAM Module |

  <img src="https://github.com/user-attachments/assets/0effbde2-077a-40ac-8b31-1e59e1a2e7e3" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

###### **Test the Policy:**
- Switch to a normal user and Try changing a own password: `passwd <username>`
- If the new password does not meet the configured criteria, an error message will be displayed.

  <img src="https://github.com/user-attachments/assets/9914a4ed-9cc9-45b0-9457-e93e42666f1d" alt="fdisk command output" width="650px"></a>
  <br>

> Note ⚠️: By default it's not check the password quality of root user, to enable check remove the “#” from `enforce_for_root` line.


----

#### **Check User Are Using Old Password As new Password or Not**
- Prevent users from reusing old passwords by maintaining a password history. This ensures they create new, strong passwords instead of cycling through previous ones.

###### **Check if password history enforcement is enabled:** `grep "pam_pwhistory.so" /etc/pam.d/common-password`

<br/>

**💡Steps to Prevent Password Reuse :**

###### **Edit the Password Policy File:** `sudo nano /etc/pam.d/common-password`

###### **Add/Modify the following line (ensure a backup first):** `password required pam_pwhistory.so remember=5`
> "remember=5" → Prevents reuse of the last 5 passwords.

###### **Ensure the following argument is present in the same file:** 
```
password [success=1 default=ignore] pam_unix.so obscure 
```
> `use_authtok` → Ensures the system verifies if the new password has been used before.

```
password [success=1 default=ignore] pam_unix.so obscure use_authtok
```

  <img src="https://github.com/user-attachments/assets/bbac5f82-f95c-47b5-86ab-1c2400b04191" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

**🔍 Testing the Policy:**

###### **Try changing a user’s password to an old one:** `passwd <username>`

###### **If configured correctly, it should reject the old password and prompt for a new one.**

  <img src="https://github.com/user-attachments/assets/35ce3f7c-5fe5-4c76-8493-60bba73862d5" alt="fdisk command output" width="650px"></a>
  <br>

----

#### **Set Auto Logout for Inactive Users**
- Inactive user sessions can be a security risk. Automatically logging out idle users helps prevent unauthorized access if a session is left open.

<br/>

**💡 Steps to Configure Auto Logout:**

###### **Configure Auto Logout for All Users**

###### **Create a script to enforce automatic logout:**
```
sudo tee /etc/profile.d/idle-users.sh <<EOF
#!/bin/bash
readonly TMOUT=9  # Set timeout to 900 seconds (15 minutes)
readonly HISTFILE   # Prevent saving command history after logout
export TMOUT
EOF
```

> `TMOUT=900` logs out inactive users after 15 minutes.
> `HISTFILE` prevents the command history from being saved after logout.

###### **Apply Correct Permissions**
> Ensure the script is executable: `sudo chmod +x /etc/profile.d/idle-users.sh`
> Apply changes immediately for all users: `source /etc/profile.d/idle-users.sh`

<br/>

**Verify the Configuration:** 

###### **Check if TMOUT is set for the current user:** `echo $TMOUT`
> Expected Output: '900'

###### **Confirm that the script exists and is executable:** `ls -l /etc/profile.d/idle-users.sh`
> Expected Output: '-rwxr-xr-x' (Executable script)

  <img src="https://github.com/user-attachments/assets/fb3d3eb2-2221-4659-b062-60cfc2cb614a" alt="fdisk command output" width="650px"></a>
  <br>

> Summary:
> - Enforced 15-minute auto-logout for inactive users
> - Prevented command history saving after logout
> - Applied global enforcement across all user sessions

<br/>

**Additional Hardening Options** 

###### **Set auto logout for all interactive shells by adding to `/etc/bash.bashrc` or `/etc/profile`:** `echo "readonly TMOUT=900" | sudo tee -a /etc/bash.bashrc`

###### **Ensure the setting is enforced globally:** `echo "readonly HISTFILE" | sudo tee -a /etc/bash.bashrc`

###### **Logout users even in TTY sessions:** `echo "export TMOUT=900" | sudo tee -a /etc/profile`


---

#### **Configure Account Lockout Policy 🔒**
- The account lockout policy helps protect against brute-force attacks by locking a user account after multiple failed login attempts. This reduces the risk of unauthorized access.


###### **Check if pam_faillock.so is properly configured in the PAM files:** `grep "pam_faillock.so" /etc/pam.d/*`

###### **To check failed login attempts:** `faillock --user <username>`

<br/>

**💡 Steps to Configure Account Lockout Policy:**

###### **Modify the /etc/pam.d/common-auth file:** `sudo nano /etc/pam.d/common-auth`

###### **Add the following lines after `pam_unix.so nullok`:**
```
auth required pam_faillock.so preauth  
auth [default=die] pam_faillock.so authfail  
auth sufficient pam_faillock.so authsucc 
```

  <img src="https://github.com/user-attachments/assets/cdb8c7cd-3d99-44ae-91a1-57d8ddf5c982" alt="fdisk command output" width="650px"></a>
  <br>

  <img src="https://github.com/user-attachments/assets/c7fe3df9-e436-4f41-aebf-6dab05944540" alt="fdisk command output" width="650px"></a>
  <br>
  
<br/>

**Additional Commands :**
> 💡 Clear Failed Attempts (If Needed) : `sudo faillock --user <username> --reset`

<br/>

**💡 Testing the Lockout Policy:**
> - Attempt to log in with the wrong password 3 times. <br/>
> - After the 3rd failure, the account should be locked for 10 minutes. <br/>
> - Check failed login attempts: `sudo faillock --user <username>`

<br/>

----

**Configure Password Expiry Date**
- Password expiration policies ensure that users update their passwords regularly to maintain security. Configuring password expiry helps prevent unauthorized access due to old or compromised passwords.

###### **Check the current password expiry settings for a user:** `chage -l <username>`

###### **Check system-wide default settings:** `cat /etc/login.defs | grep PASS_`

<br/>

**💡 Steps to Configure Password Expiry Date :**

###### **Configure System-Wide Password Expiry Settings, Modify the `/etc/login.defs` file:** `sudo nano /etc/login.defs`
```
# Set the following values:  
PASS_MAX_DAYS   90   # Maximum days before password expires  
PASS_MIN_DAYS   10   # Minimum days before password can be changed  
PASS_MIN_LEN    8    # Minimum password length  
PASS_WARN_AGE   7    # Warn users 7 days before password expires  
```

  <img src="https://github.com/user-attachments/assets/8d138cc4-1309-490d-96f3-264880fd7ae9" alt="fdisk command output" width="650px"></a>
  <br>
  
<br/>

> Set Default User Account Settings 
> - We Can Set Default Inactive Time, User Shell, etc from these file.

> Password Inactive <br/> 
> - Specifies the number of days after password expiration that the account becomes inactive.
> - `INACTIVE=-1` means, account never become an inactive anytime user can login and change there password.

> Modify "/etc/default/useradd": `sudo nano /etc/default/useradd` 

  <img src="https://github.com/user-attachments/assets/f2c19344-93fe-4d2f-979a-9fc4de8bce33" alt="fdisk command output" width="650px"></a>
  <br>
  
<br/>

##### **To Check the Password Expiry Policy:** `chage -l loki`

  <img src="https://github.com/user-attachments/assets/eaad2df6-45fa-4aed-a6b6-1f1a33793f7b" alt="fdisk command output" width="650px"></a>
  <br>
  

<br/>

---

**Configure Account Expiry Date Of Temporary Account 👤**
- Temporary accounts should have a predefined expiration date to prevent unauthorized access after their intended use. This ensures security by automatically disabling accounts after a specified period.

<br/>

**💡 Set Password Expiry for Individual Users :**

###### **Set Account Expiry Date While Creating a User: `useradd -e 2024-01-16 <username>`**

###### **Change Account Expiry Date for an Existing User: `usermod -e 2024-01-16 <username>`**

  <img src="https://github.com/user-attachments/assets/c652d03a-38df-4f0b-97c8-6efbd8dc16b6" alt="fdisk command output" width="650px"></a>
  <br>

###### **Set Password Expiry Using chage: `chage -E 2024-01-16 -I 4 -m 3 -M 90 -W 4 <username>`**

<br/>

###### **(Additional Commands) Disable Password Expiry for a User (if required): `chage -M -1 <username>`**


<br/>

---

**Monitor and Remove Inactive Users**
- Inactive user accounts can pose security risks if left unattended. Regularly monitoring and removing unused accounts helps prevent unauthorized access and minimizes attack surfaces.

1️⃣ Check Last Login of Users: Shows the last login time of all users. If a user has never logged in, it will display "Never logged in."
```
lastlog
```

2️⃣ Find Inactive Home Directories: Finds home directories that haven't been modified in 90 days (adjust as needed).
```
find /home -type d -ctime +90
```

<br/>

**💡 Steps to Manage Inactive Users:**

> Define an Inactivity Policy
> - Set a policy that specifies the maximum number of inactive days before an account is disabled.
> - Document procedures for handling inactive accounts (e.g., notification, grace period, deletion).



###### **Set Automatic Account Inactivity Lock:**
> Locks the account if inactive for 30 days. `chage -I 30 <username>`

  <img src="https://github.com/user-attachments/assets/889409d3-d129-488e-9c7e-250fa5a6ea96" alt="fdisk command output" width="650px"></a>
  <br>


<br/>

###### **Manually Disable an Inactive Account : `passwd -l <username>`**
> Locks the account but keeps the data.

<br/>

> Delete Unused User Accounts:
> - Deletes the user and their home directory permanently. `userdel -r <username>`

<br/>

> Notify Users Before Removal ⚠
> - Send email alerts to inactive users before account deletion, allowing them to reactivate if necessary.


<br/>

---

**Disable Unused System Accounts**
- System accounts are typically used for running services and do not require interactive login access. Disabling login for unused system accounts helps reduce security risks by preventing unauthorized access.


###### **Check if an Account is Locked: `passwd -S <username>`**

<br/>

**💡 Steps to Disable Unused System Accounts:**

###### **1️⃣ Use nologin Instead of Deleting Accounts**
> - Instead of deleting system accounts, set their shell to /usr/sbin/nologin to ensure services continue functioning without allowing login.
> - usermod -s /usr/sbin/nologin <username>

  <img src="https://github.com/user-attachments/assets/b1faee6a-c106-448e-9b42-ec05bb515ad3" alt="fdisk command output" width="650px"></a>
  <br>


###### **2️⃣ Disable a System Account Completely:**
> - This locks the password, making login impossible. `passwd -l <username>`


###### **3️⃣ Monitor Login Attempts for System Accounts**
> - To check if system accounts are being accessed unexpectedly.
> - Use `grep "session opened" /var/log/auth.log` (Debian/Ubuntu)

  <img src="https://github.com/user-attachments/assets/9a62c115-ec53-4ce5-9f02-4000e9ec22cf" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---

**Restrict Use of Empty Passwords**
 - Empty password fields in /etc/shadow pose a security risk as they allow unauthorized users to log in without authentication. To enhance security, ensure that all user accounts have a password set.

<br/>

###### **Check for empty password fields in /etc/shadow: `awk -F: '($2==""){print $1}' /etc/shadow`**

###### **Restrict accounts with empty passwords:**
> - Disable login for users with empty passwords: `passwd -l <username>`
> - Enforce a password policy to prevent creating accounts without passwords.
> - Force password change for affected users: `passwd <username>`


<br/>

###### **🛠️ Testing Purpose (Account with Empty Password)**

###### **Create an account : `useradd -m -d /home/lol -s /bin/bash lol`**

###### **Remove password requirement (by default, accounts are locked with ! in /etc/shadow): `passwd -d lol`**

###### **This will list all accounts with empty passwords: `cat /etc/shadow | awk -F : '($2==""){print $1}'`**

  <img src="https://github.com/user-attachments/assets/b05825c9-19f5-4620-95aa-767f646a51a3" alt="fdisk command output" width="650px"></a>
  <br>

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Network Security 🛡️

#### **Restrict Service Access to Authorized Users via Firewalls & Controls**
- Restrict access to services running on the host by allowing only authorized users or systems to connect. This can be achieved using firewalls, access control lists (ACLs), or security policies.

  <br/>

**💡 Steps to Implement:**

###### **Use a Firewall (UFW: Uncomplicated Firewall) to Restrict Access**
> Installing UFW `apt install ufw -y`

> Creating Rules in `UFW`
```
sudo ufw default deny incoming
sudo ufw default allow outgoing

sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
```

> Allowing/Denying Specific IPs
````
sudo ufw allow from <specific-ip> 
sudo ufw deny from <malicious-ip> 
````

> Allowing Traffic From Specific IP/CIDR to Specific Port
```
sudo ufw allow from 10.20.30.5 to any port 22
sudo ufw allow from 10.20.30.1/24 to any port 22 # | Make Sure Ip-address is Static
sudo ufw allow from 192.168.1.0/24 to any port 3306 proto tcp
```

  <img src="https://github.com/user-attachments/assets/680ea3ad-9ee5-41f6-a358-52e79b12e1e0" alt="fdisk command output" width="650px"></a>
  <br>

> Allowing Specific Port Ranges:
```
sudo ufw allow 1000:2000/tcp
```

> To Check number of these rules are: `sudo ufw status numbered`

> To Delete Any Rule: `sudo ufw delete <rull-no>`

> Checking Logs for Blocked Requests: `sudo cat /var/log/ufw.log | grep "BLOCK"`

<br/>

**💡 Limit Access Using TCP Wrappers (if applicable)** 
> - Modify `/etc/hosts.allow` and `/etc/hosts.deny` to restrict access.
> - Example: Allow only 192.168.1.100 to use SSH (sshd: 192.168.1.100)
> - Deny all others: `sshd: ALL`

<br/>

**💡 Configure Application-Specific Access Control**
> - Some services, like Apache, MySQL, or PostgreSQL, have built-in access controls.
> - Example (MySQL): Restrict access to specific IPs:
```
CREATE USER 'user'@'192.168.1.100' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON dbname.* TO 'user'@'192.168.1.100';
```

<br/>

**💡 Implement Role-Based Access Control (`RBAC`)**
> - Use SELinux or AppArmor to restrict service access based on roles.

<br/>

---

#### **Disable IP forwarding**
- IP forwarding allows a system to route network traffic between interfaces, which is unnecessary for most standalone servers and can be a security risk if enabled unintentionally.

<br/>

**💡 Steps to Disable IP Forwarding:**

###### **Temporarily Disable IP Forwarding (Until Reboot)**
```
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv6.conf.all.forwarding=0
```

###### **Permanently Disable IP Forwarding**
> Open the configuration file: `sudo nano /etc/sysctl.conf`
> Add or modify the following lines: 
```
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
```

  <img src="https://github.com/user-attachments/assets/1584251e-b4ea-4d17-b117-15d538c1b787" alt="fdisk command output" width="650px"></a>
  <br>

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/b9fb4827-1bf7-4209-9b14-d1c424f10328" alt="fdisk command output" width="650px"></a>
  <br>

> Verify the Configuration
```
cat /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv6/conf/all/forwarding
```
> - If the output is `0`, IP forwarding is disabled.

  <img src="https://github.com/user-attachments/assets/8df28588-2b42-46f4-a8fb-70dce2595d37" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---

#### **Disable Send Packet Redirects**
- Packet redirects allow the system to inform other devices about better routes for packets. However, this can be exploited for man-in-the-middle (MITM) attacks, so it's recommended to disable it unless explicitly required.


**💡 Steps to Disable Send Packet Redirects:**
> Permanently Disable Packet Redirects
> - Open the configuration file: `sudo nano /etc/sysctl.conf`
> - Add or modify the following lines:
```
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
```
  <img src="https://github.com/user-attachments/assets/ec441e7a-f822-4167-82e3-00ae7cba9827" alt="fdisk command output" width="650px"></a>
  <br>

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/783f1677-b0df-4290-a19a-e7bb12be7a0d" alt="fdisk command output" width="650px"></a>
  <br>

> Verify the Configuration 
```
cat /proc/sys/net/ipv4/conf/all/send_redirects
cat /proc/sys/net/ipv4/conf/default/send_redirects
```
> - If the output is `0`, packet redirects are disabled.

  <img src="https://github.com/user-attachments/assets/62025c9c-1feb-40a1-8958-76a05e1dc786" alt="fdisk command output" width="650px"></a>
  <br>


###### **For Temporary purpose (Until Reboot), RUN the following command**
```
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
```

<br/>

---

#### **Disable Source Routed Packet Acceptance**
- Source-routed packets allow the sender to specify the route the packet should take, which can be exploited for spoofing or man-in-the-middle (MITM) attacks. Disabling this helps prevent security risks.

<br/>


**💡 Steps to Disable Source Routed Packet Acceptance :**

###### **Permanently Disable Source Routing:**
> - Open the configuration file: `sudo nano /etc/sysctl.conf`
> - Add or modify the following lines:
```
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
```

  <img src="https://github.com/user-attachments/assets/abf44834-422c-418f-9db3-b9ecadc03814" alt="fdisk command output" width="650px"></a>
  <br>

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/abc736a9-f968-4100-9be5-440390c571ea" alt="fdisk command output" width="650px"></a>
  <br>

> Verify the Configuration:
```
cat /proc/sys/net/ipv4/conf/all/accept_source_route
cat /proc/sys/net/ipv4/conf/default/accept_source_route
cat /proc/sys/net/ipv6/conf/all/accept_source_route
cat /proc/sys/net/ipv6/conf/default/accept_source_route
```
> - If the output is `0`, source-routed packet acceptance is disabled.

<br/>

---

#### **Disable ICMP Redirect Acceptance**
- ICMP redirects are used by routers to inform hosts of a better route. However, attackers can exploit this to alter network routes maliciously. Disabling ICMP redirect acceptance enhances security.

<br/>

**💡 Steps to Disable ICMP Redirect Acceptance :**

> **Permanently Disable ICMP Redirects**
> - Open the sysctl configuration file: sudo nano /etc/sysctl.conf
> - Add or modify the following lines:
```
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
```

  <img src="https://github.com/user-attachments/assets/18ccec64-e060-4c1e-b58f-a9767bcb605f" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/00542d63-c69f-4a60-840d-afdeb2d8f094" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> Verify the Configuration
```
cat /proc/sys/net/ipv4/conf/all/accept_redirects
cat /proc/sys/net/ipv4/conf/default/accept_redirects
cat /proc/sys/net/ipv6/conf/all/accept_redirects
cat /proc/sys/net/ipv6/conf/default/accept_redirects
```
> - If the output is `0`, ICMP redirect acceptance is disabled.

<br/>

---

#### **Enable Ignore Broadcast Requests**
- Broadcast requests can be exploited in amplification attacks like Smurf attacks, where an attacker spoofs an IP and sends ICMP echo requests to the broadcast address, causing a flood of responses. Enabling ignore broadcast requests mitigates this risk.

<br/>

**💡 Steps to Enable Ignore Broadcast Requests :**

> **Permanently Ignore Broadcast Requests**
> - Open the sysctl configuration file: sudo nano /etc/sysctl.conf
> - Add or modify the following line:
```
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

<br/>

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/33e478c2-369a-4155-8e33-4d3397a0f1cc" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> Verify the Configuration
```
cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
```
> - If the output is `1`, broadcast requests are ignored. 


<br/>

---

#### **Enable Bad Error Message Protection**
- This setting helps protect against malicious ICMP error messages, which can be exploited for reconnaissance or attacks like ICMP source quench DoS.

<br/>

**💡 Steps to Enable Bad Error Message Protection :**

> **Permanently Enable Protection**
> - Open the sysctl configuration file: `sudo nano /etc/sysctl.conf`
> - Add or modify the following line:
```
net.ipv4.icmp_ignore_bogus_error_responses = 1
```

<br/>

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/a6f4dbcf-704f-4cfb-85c4-fc3cf680c7f2" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> Verify the Configuration
```
cat /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
```
> - If the output is `1`, bad ICMP error message protection is enabled.


<br/>

---

#### **Enable TCP/SYN Cookies**
- Enabling TCP SYN cookies helps protect against SYN flood attacks, a type of DoS attack that overwhelms a system by sending excessive SYN requests.

<br/>

**💡 Steps to Enable TCP SYN Cookies :**

> **Permanently Enable TCP SYN Cookies**
> - Open the sysctl configuration file: `sudo nano /etc/sysctl.conf`
> - Add or modify the following line:
```
net.ipv4.tcp_syncookies = 1
```

> Apply changes: `sudo sysctl -p`

  <img src="https://github.com/user-attachments/assets/87f522df-d6ea-434a-a826-924822d2c466" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> Verify the Configuration
```
cat /proc/sys/net/ipv4/tcp_syncookies
```
> - If the output is `1`, TCP SYN Cookies are enabled.


<br/>

---

#### **Close Unused Open Ports**
- Closing unused ports helps reduce the attack surface and enhances system security.

<br/>

**💡Steps to Identify and Close Unused Open Ports :**

> **Check Listening Ports**
```
netstat -tulnp    # For older systems  
ss -tulnp         # For modern systems
```

```
t → TCP
u → UDP
l → Listening
n → Show numerical addresses
p → Show process name
```


> **Identify Unused Services**
> - Look for services you don’t need and disable them.
> - Example output: `tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:* 1234/telnet`
> - This means telnet is running on port 23, which is insecure.

<br/>

> **Disable/Stop Unnecessary Services**
```
sudo systemctl stop telnet  
sudo systemctl disable telnet 
```

<br/>

> **Block Unwanted Ports via Firewall (UFW Example)**
```
sudo ufw deny 23   # Block Telnet (port 23)
sudo ufw deny 21   # Block FTP (port 21)
```

<br/>

> **Verify Closed Ports: `ss -tulnp | grep LISTEN`**

  <img src="https://github.com/user-attachments/assets/4fb5e650-58b5-411a-9345-a561f3657583" alt="fdisk command output" width="650px"></a>
  <br>

> ⚠ Ensure only necessary ports are open.

<br/>

---

#### **Log Suspicious Packets (`log_martians`)**

> **🔍 What Are "Martian" Packets?**
- `Martian packets` are IP packets that have bogus or impossible source addresses — such as:
> - Private IPs coming from the public internet
> - IP addresses that should never appear on your interface (e.g., loopback or reserved addresses)
> - Packets with bad routing or spoofed origins

<br/>

> These could be a sign of:
> - Misconfigured devices
> - Network scanning
> - IP spoofing
> - Malware activity

<br/>

> **🛡️ Why Enable Logging?**
- Enabling `log_martians` allows the kernel to log these suspicious packets to dmesg or `/var/log/kern.log`. This is very helpful for network forensics and intrusion detection.

**🔧 Steps to Implement:**
- Add the settings to a custom sysctl config file: `sudo nano /etc/sysctl.conf`
- Add the following lines:
```
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

> Apply the changes: `sudo sysctl --system`

  <img src="https://github.com/user-attachments/assets/49b6b369-ac14-4006-b45a-d7fa96051d48" alt="fdisk command output" width="650px"></a>
  <br>


> 🛠️ Verify It's Active
```
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians
```
> Output should look like
```
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
```

<br/>

> 📄 Where Are Logs Stored?*
> - Martian packet logs appear in: `/var/log/kern.l`
>
> OR
```
dmesg
```
> - Search for keywords like martian or ll header in logs.

<br/>

---

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Remote Access and Secure Communication 🤖


#### **Secure SSH**
- While SSH provides a secure channel, its default configuration can leave systems vulnerable. Hardening SSH is crucial for robust security. If SSH is not required, disabling it is the most secure option. Otherwise, modify the `/etc/ssh/sshd_config` file to implement stronger security measures. This includes changing default ports, disabling root login, and configuring key-based authentication.

<br/>

**💡 Steps to Secure SSH:**

> **1. Disable Root User Login Over SSH**
> - Prevents direct root access, reducing attack vectors.
> - Edit:  `/etc/ssh/sshd_config`
> - Set: Remove the `#` and Modify the value `PermitRootLogin no`
> - Verification: `cat /etc/ssh/sshd_config | grep PermitRootLogin`


<br/>

> **2. Restrict SSH Access to Specific Users**
> - Limits SSH access to only authorized users.
> - Edit `/etc/ssh/sshd_config`
> - Add: `AllowUsers user1 user2`
> - Verification: `cat /etc/ssh/sshd_config | grep AllowUsers`

  <img src="https://github.com/user-attachments/assets/1d64e05a-5fa0-40e1-aaae-e129695f4b47" alt="fdisk command output" width="650px"></a>
  <br>

> Note ⚠️
> - If we only allow few specific user on SSH follow the steps:
> - Generate a new key for `loki`, On your local machine: `ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_loki`

> Then copy the public key to the server: `ssh-copy-id -i ~/.ssh/id_rsa_loki.pub loki@192.168.0.106`



> And login with private key: `ssh -i .ssh/id_rsa_loki loki@192.168.0.106`

  <img src="https://github.com/user-attachments/assets/88f28e37-f134-45ba-9fd1-2cd987a92451" alt="fdisk command output" width="650px"></a>
  <br>

> ⚠️ Before disabling the root user, ensure you have a separate user account with administrative privileges to manage system configurations in the future. 

<br/>

> **3. Change Default SSH Port**
> - Avoids common brute-force attacks on port 22.
> - Edit `/etc/ssh/sshd_config`
> - Change: Port `2222` (or any non-standard port)
> - Verification: `cat /etc/ssh/sshd_config | grep Port`

<br/>

> **4. Use SSH Keys for Authentication**
> - Stronger security compared to password-based authentication.
> - RUNs the following command:
```
 # Generate SSH Keys
ssh-keygen -t rsa
# Copy Your SSH Keys
ssh-copy-id user@ip-address
```
> - Verification: `ls -l ~/.ssh/`

<br/>

> **5. Disable Password Authentication in SSH**
> - Forces users to use SSH keys for authentication.
> - Modify `/etc/ssh/sshd_config` & Set `PasswordAuthentication no`
> - Verification: `cat /etc/ssh/sshd_config | grep PasswordAuthentication`

<br/>

> **6. Enable Two-Factor Authentication (`2FA`) (Optional but Recommended)**
> - Adds an extra layer of security.
> - Insall Google Authenticator:
```
sudo apt install libpam-google-authenticator -y
google-authenticator
```

  <img src="https://github.com/user-attachments/assets/f7cc4e2c-2169-48a7-8334-5b922a09bbd2" alt="fdisk command output" width="650px"></a>
  <br>

> - Take a backup of the file: `cp /etc/pam.d/sshd /etc/pam.d/sshd.bak`
> - Now open in the file in editor: `nano /etc/pam.d/sshd`
> - Add the following line:
```
# Before
# Standard Un*x authentication.
@include common-auth


#After
# Standard Un*x authentication.
@include common-auth
auth required pam_google_authenticator.so
```

  <img src="https://github.com/user-attachments/assets/f2fd20b3-bcb3-4bb6-a9d6-f949e7d30baa" alt="fdisk command output" width="650px"></a>
  <br>

> Now open `/etc/ssh/sshd_config` file in editor
```
#Modify the following line

KbdInteractiveAuthentication yes
UsePAM yes
```

<br/>

> **7. Limit SSH Login Attempts**
> - Helps prevent brute-force attacks.
> - Edit `/etc/ssh/sshd_config` & Set `MaxAuthTries 3`
> - Verification: `cat /etc/ssh/sshd_config | grep MaxAuthTries`

<br/>

> **8. Disable Empty Passwords & Host-Based Authentication**
> - Ensures all accounts require authentication.
> - Edit `/etc/ssh/sshd_config` & Set
```
PermitEmptyPasswords no
IgnoreRhosts yes
HostbasedAuthentication no
```

> Verification: `cat /etc/ssh/sshd_config | grep -E 'PermitEmptyPasswords|IgnoreRhosts|HostbasedAuthentication'`

<br/>

> **9. Configure SSH Timeout Settings**
> - Automatically disconnects idle sessions to prevent misuse.
> - Modify `/etc/ssh/sshd_config`
```
ClientAliveInterval 900
ClientAliveCountMax 0
```

> Verification: `cat /etc/ssh/sshd_config | grep -E 'ClientAliveInterval|ClientAliveCountMax'`

<br/>

> **10. Set Strong Encryption Algorithms**
> - Ensures secure communication over SSH.
> - Modify `/etc/ssh/sshd_config`: `Ciphers aes256-ctr,aes192-ctr,aes128-ctr`

> Verification: `cat /etc/ssh/sshd_config | grep Ciphers`

<br/>

> **11. Restrict SSH Access Using Firewall**
> - Prevents unauthorized access from unknown IPs.
> - Implementation (UFW): `sudo ufw allow from 192.168.1.0/24 to any port 22`
> - Verification: `sudo ufw status`

<br/>

> **12. SSH's X11 forwarding allows remote GUI applications**
> - `X11Forwarding no` refers to a setting within the SSH (Secure Shell) server configuration file (/etc/ssh/sshd_config) that disables the ability to forward graphical user interface (GUI) applications over an SSH connection.
> - Modify `/etc/ssh/sshd_config` & Set `X11Forwarding no`.
> - Verification: `cat /etc/ssh/sshd_config | grep X11Forwarding`

<br/>

> **13. Ensure Proper Permissions on SSH Config Files**
> - Prevents unauthorized modifications.
> - RUNs the following command:
```
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 600 ~/.ssh/*
```

> - Verification:
```
ls -l /etc/ssh/sshd_config
ls -la ~/.ssh/
```

<br/>

> **14. Final Steps: Restart & Test SSH Configuration**
> - Check if we have missed anything or not
```
cat /etc/ssh/sshd_config | grep -nE 'X11Forwarding|Ciphers|ClientAliveInterval|ClientAliveCountMax|PermitEmptyPasswords|IgnoreRhosts|HostbasedAuthentication|MaxAuthTries|PasswordAuthentication|Port|AllowUsers|PermitRootLogin'

sudo sshd -t  # Check for syntax errors
sudo systemctl restart sshd
```

  <img src="https://github.com/user-attachments/assets/b32683ee-b923-4425-9746-6c0fb508104e" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---

#### **Use VPNs for Secure Remote Access**
- Using a VPN for secure remote access ensures that all traffic between the client and the server is encrypted, reducing the risk of interception by attackers.

<br/>

**💡 Steps to Secure Remote Access with a VPN:**

> Choose a Secure VPN Solution
> - OpenVPN, WireGuard, or IPsec-based VPNs (e.g., StrongSwan) are recommended.

<br/>

> Install and Configure the VPN
> - Install OpenVPN: `sudo apt install openvpn -y`
> - Configure VPN settings in `/etc/openvpn/ `

<br/>

> Restrict Access via VPN
> - Ensure only VPN clients can access SSH and other sensitive services.
> - Example (UFW): `sudo ufw allow from 10.8.0.0/24 to any port 22 proto tcp`

  <img src="https://github.com/user-attachments/assets/75f8ddb9-6c65-4c53-8adb-492114a6c7d9" alt="fdisk command output" width="650px"></a>
  <br>


> Verify VPN Connectivity
> - Check VPN status: `systemctl status openvpn`


<br/>

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Logging and Monitoring ⚠️

#### **Enable System Auditing**
- System auditing helps track security-relevant events, detect suspicious activity, and maintain compliance with security policies. The auditd service records system events, while ausearch and aureport provide analysis capabilities.

<br/>

**💡 Steps to Enable and Configure Audit Logging:**

> **Install and Enable auditd: `sudo apt install auditd -y`**
> - Ensure the auditd package is installed.

  <img src="https://github.com/user-attachments/assets/fa08a5a4-ae2f-41e2-899a-59210b68a8f5" alt="fdisk command output" width="650px"></a>
  <br>

> - Start and enable `auditd` to persist across reboots:
```
sudo systemctl enable --now auditd
sudo systemctl status auditd  # Verify status
```

  <img src="https://github.com/user-attachments/assets/4d1618e2-2fc8-4e08-81c4-f09839bd0dbc" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> **Define Audit Rules**
> - Configure audit rules in `/etc/audit/rules.d/audit.rules` or `/etc/audit/audit.rules`.
> - Example rules to track critical security events:
```
-w /etc/passwd -p wa -k passwd_changes  # Monitor user account modifications  
-w /etc/shadow -p wa -k shadow_changes  # Track password file changes  
-w /var/log/auth.log -p wa -k auth_logs # Monitor authentication logs  
-a always,exit -F arch=b64 -S execve -k exec_monitor # Log all executed commands

# Remove the "#" before adding the rules either it will not work.

sudo mv /etc/audit/rules.d/audit.rules /etc/audit/rules.d/hardening.rules

# Make sure it has the correct permissions:
sudo chmod 644 /etc/audit/rules.d/hardening.rules
sudo chown root:root /etc/audit/rules.d/hardening.rules
```

> - Apply changes: 
```
sudo augenrules --load
sudo auditctl -l  # Check Rule Listed or not
sudo systemctl restart auditd
```

  <img src="https://github.com/user-attachments/assets/5608381e-5ed2-43c5-8b6b-495b5fa40213" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> **Search and Analyze Logs**
> - Check the audit logs for security events:
```
sudo ausearch -i -ts recent    # View recent logs in a readable format

sudo usermod -c "test change" arijit  
sudo ausearch -k passwd_changes  # Search for specific audit key events 
```

  <img src="https://github.com/user-attachments/assets/5bd4e27c-1b09-4371-bbde-a18eea8c567c" alt="fdisk command output" width="650px"></a>
  <br>

> Generate audit reports:
```
sudo aureport --auth --summary  # Authentication summary  
sudo aureport --file            # File access audit report 
```

  <img src="https://github.com/user-attachments/assets/d9b1a5c3-9223-4170-b1f9-169c3256a05a" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> **💡 Additional Hardening**
> - Set audit logs to immutable mode to prevent tampering: `sudo auditctl -e 2 `  

  <img src="https://github.com/user-attachments/assets/345e65a6-5183-4908-ad19-4de6b427f682" alt="fdisk command output" width="650px"></a>
  <br>

> - Enable remote logging for centralized monitoring using `rsyslog` or `SIEM` tools.
> - Regularly review audit logs and configure alerts for critical security events.

<br/>

---

#### **Enable Logging for Critical System Files**
- System logs help track authentication attempts, system errors, and security events. Ensuring proper logging allows for forensic analysis and real-time monitoring.

<br/>

**💡 Steps to Enable and Verify Logging:**

> **Ensure Logging Services Are Running**
> - Most Linux systems use `rsyslog` or `journald` for logging. Ensure they are installed and running:
```
sudo systemctl enable --now rsyslog
sudo systemctl status rsyslog # Verify rsyslog is active
```

<br/>

> **Verify Critical Logs Are Being Written**
> - Check if key log files exist and are being updated: `ls -l /var/log/auth.log /var/log/syslog`
> - View recent authentication logs (failed/successful login attempts, SSH access): `sudo tail -f /var/log/auth.log` 

  <img src="https://github.com/user-attachments/assets/44304017-9c61-4f25-be4f-33109d6f51da" alt="fdisk command output" width="650px"></a>
  <br>

> - Check system-wide logs for errors, warnings, and system events: `sudo tail -f /var/log/syslog`

  <img src="https://github.com/user-attachments/assets/16b1590e-6246-45ea-b946-b2c0d71bfe9f" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> **Configure Log Rotation to Prevent Overflows**
> - Linux uses `logrotate` to manage log file sizes and retention.
> - Edit or check `/etc/logrotate.d/rsyslog` to configure log rotation settings: `sudo nano /etc/logrotate.d/rsyslog`

> Example configuration:
```
/var/log/syslog {
      weekly
      rotate 4
      compress
      missingok
      notifempty
  }
```

> - Apply changes: `sudo logrotate -f /etc/logrotate.conf`

<br/>

---

#### **Monitor Login Failures**
- Monitoring failed login attempts is crucial for detecting brute-force attacks and unauthorized access attempts. faillog helps track and analyze failed login attempts for local user accounts.

<br/>

**💡 Steps to Enable and Verify Login Failure Monitoring :**

> **Check/Display all failed login attempts: `faillog -a`** 
> - This command lists all users with recorded login failures, including the number of failed attempts and the last failure time.

  <img src="https://github.com/user-attachments/assets/386fc46e-ad6a-4a12-af95-178a72a7965c" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

> **Check a Specific User’s Failed Logins**
> - To view failed login attempts for a specific user (e.g., username): `faillog -u username`

<br/>

> **Reset Login Failure Count for a User**
> - If an account is locked due to too many failures, reset its counter: `sudo faillog -r -u username`

<br/>

> **Monitor real-time authentication logs**
```
sudo tail -f /var/log/auth.log  # Debian/Ubuntu
```

<br/>

---

#### **Implement ClamAV For Ubuntu**

> **ClamAV for Ubuntu (Open-Source Anti-Malware Scanner)**  
> - ClamAV is a free and widely used antivirus tool for detecting malware, trojans, and viruses.

<br/>

> **Installation:**  
> - Install ClamAV and its daemon: `sudo apt update && sudo apt install clamav clamav-daemon -y `
> - Update ClamAV Virus Database: `sudo freshclam`  

<br/>

> **Performing a Scan:**  
> - Scan a specific directory: sudo clamscan -r /home/user  
> - Scan the entire system (may take time): sudo clamscan -r / --exclude-dir="^/sys|^/proc|^/dev" 

<br/>

> **Enable ClamAV Auto-Scanning:**  
> - Edit ClamAV scheduling: sudo nano /etc/clamav/clamd.conf 
> - Ensure `ScanOnAccess yes` is set for real-time scanning.
> - Restart ClamAV Service: `sudo systemctl restart clamav-daemon`  

<br/>

> **Check ClamAV is working or not**
> - Check ClamAV service status: `sudo systemctl status clamav-daemon`
> - Review scan logs: `sudo cat /var/log/clamav/clamav.log`   

<br/>

> **💡 Additional Recommendations:**  
> - Automate ClamAV scans using cron jobs: `echo "0 2 * * * root clamscan -r /home/user" | sudo tee -a /etc/crontab`  

<br/>

> **🔗 Reference:**
> - https://github.com/Cisco-Talos/clamav
  
<br/>

----

#### **Scanning for Misconfigurations & Vulnerabilities**
- Regularly scanning for security misconfigurations and vulnerabilities helps identify weaknesses before attackers exploit them.

<br/>

**💡 Steps to Configure Lynis/OpenVAS:**

> **Install & Use Lynis (Lightweight Security Audit for Linux)**
> - Lynis is a security auditing tool that scans for misconfigurations.

> Install Lynis: `sudo apt install lynis -y`
> Run a full security audit: `sudo lynis audit system`

  <img src="https://github.com/user-attachments/assets/03b25185-8557-4b82-856b-4e1acac77a0d" alt="fdisk command output" width="650px"></a>
  <br>

> - Provides security recommendations for system hardening.
> - Results are saved in `/var/log/lynis.log`

  <img src="https://github.com/user-attachments/assets/5336b7b8-33f9-42b8-b42c-d08d6a31460e" alt="fdisk command output" width="650px"></a>
  <br>

> ⚠ While running Lynis, `ClamAV` was not installed, reason why it's showing `Malware Scanner` as ❌. 

<br/>

> - Verification: `sudo cat /var/log/lynis-report.dat | grep -i "suggestion"`
> - It will lists misconfigurations found by Lynis.

<br/>

> **Scan for Vulnerabilities Using OpenVAS (Full-Featured Scanner)**
- OpenVAS (by Greenbone) is a comprehensive vulnerability scanner.

> Install OpenVAS (Greenbone Community Edition): `sudo apt install openvas -y`
> Start the OpenVAS scanner:
```
sudo systemctl start gvmd
sudo systemctl start ospd-openvas
```

> Access the Web Interface:
> - Open browser: https://<your-server-ip>:9392/
> - Default login: admin / <auto-generated password>
> - Configure & run a full vulnerability scan.

<br/>

> After scanning, check reports in `/var/lib/openvas/report/`

<br/>

![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Kernel Hardening

#### Enable and Configure SELinux
- SELinux is a powerful Mandatory Access Control (MAC) system integrated into the Linux kernel. It enforces security policies that restrict user and process permissions beyond traditional Unix permissions, significantly reducing the impact of misconfigurations or service compromises.

<br/>

**💡 Steps to Implement SELinux:**

> **Check Current SELinux Status: `sestatus`** 

> **If it's not install, installed it:**
```
sudo apt install selinux-basics selinux-policy-default -y
apt install policycoreutils -y
```

> Set SELinux to Enforcing Mode
> Edit the SELinux configuration file: `sudo nano /etc/selinux/config`
> Update the following line:
```
SELINUX=enforcing
```

> Apply Changes
> - If SELinux was disabled, you’ll need to reboot for the change to take effect: `sudo reboot`
> - If it was already in permissive mode, you can enable enforcing mode without reboot: `sudo setenforce 1`
> - Verify the Change: `sestatus`

<br/>

---

#### **Disable IPv6 if Not Needed**
- Disabling IPv6 reduces the attack surface and prevents unintended network exposure if your system does not require it. This is useful for environments where only IPv4 is used.

**Disable IPv6 if Not Needed:**
> Modify `/etc/sysctl.conf` or create a new file in `/etc/sysctl.d/`
```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
```

  <img src="https://github.com/user-attachments/assets/7d70a279-cd38-48f8-a36a-41daf27ab09d" alt="fdisk command output" width="650px"></a>
  <br>

> Apply the changes immediately without rebooting: `sudo sysctl -p /etc/sysctl.conf`

  <img src="https://github.com/user-attachments/assets/e677c81b-23b0-4d1b-8ec7-6575726b07af" alt="fdisk command output" width="650px"></a>
  <br>

> Check if IPv6 is disabled in sysctl: `sysctl -a | grep disable_ipv6`

  <img src="https://github.com/user-attachments/assets/c28e4730-2943-4d32-9af4-727a74df3d39" alt="fdisk command output" width="650px"></a>
  <br>

<br/>

---

#### **Enable Address Space Layout Randomization (ASLR)**
- ASLR increases security by randomizing memory addresses used by system processes, making it harder for attackers to predict memory locations for exploits like buffer overflows.

<br/>

**💡 Steps to Enable ASLR:**

> **Permanently enable it (persist across reboots):**
> - Edit your sysctl config (either of these files):
```
sudo nano /etc/sysctl.conf
# OR
sudo nano /etc/sysctl.d/99-hardening.conf
```

> Add the following line: `kernel.randomize_va_space = 2`
> Then apply the change: `sudo sysctl -p /etc/sysctl.conf`

<br/>

**💡 Steps for Verification:**
> `sysctl -a | grep kernel.randomize_va_space` (Check if ASLR is enabled)
> `cat /etc/sysctl.conf | grep kernel.randomize_va_space` (Ensure persistence across reboots)

  <img src="https://github.com/user-attachments/assets/d029ecd7-c968-48cb-b88c-c349eb2aec7c" alt="fdisk command output" width="650px"></a>
  <br>


![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

