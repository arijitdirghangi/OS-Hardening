lol


![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

### Create separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home` 💡 <br/>
- Creating separate partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home` provides better isolation, security, and management of system resources. These partitions allow for independent management, such as setting appropriate mount options and file system types, which can help protect sensitive data, ensure log retention, and optimize performance. It also prevents one partition from filling up and impacting others.


💡 Steps to Implement:

1. Identify Available Disks:
- Use **sudo fdisk -l** to list available disks.
2. Create Partitions for `/var`, `/var/log`, `/var/log/audit`, and `/home`:

`1ST Scenario:` Create Seprarate partition during OS Installations 💡 <br/>
- I have taken two hard-disk one for os installation and another for storing specific directory content.
  - 20GB Hard-disk OS Installation.
  - 70GB Hard-disk for storing specific directory content. 

- In my case i already created separated the partition `/var`, `/var/log`, `/var/log/audit`, and `/home` into `70GB` hard-disk. <br/>
- `fdisk -l`- output:

 ![image](https://github.com/user-attachments/assets/ed54c9fa-13a2-44f0-9412-27e453ffde2f)

- `df -h` command output

![image](https://github.com/user-attachments/assets/ab7efbbb-67fc-4b52-acdd-3000318fa69e)


`2ND Scenario:` After OS installation manually  partitioned the disk and moved directories like `/home`, `/var`, etc. to separate partitions.





![---------------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)


