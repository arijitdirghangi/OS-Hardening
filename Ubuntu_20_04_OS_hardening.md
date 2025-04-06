lol


![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

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


