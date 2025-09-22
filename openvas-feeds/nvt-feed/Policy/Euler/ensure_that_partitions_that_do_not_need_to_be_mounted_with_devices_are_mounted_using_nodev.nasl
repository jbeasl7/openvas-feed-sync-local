# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# ------------------------------------------------------------------
# METADATA
# ------------------------------------------------------------------

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130436");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Partitions That Do Not Need to Be Mounted with Devices Are Mounted Using nodev");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.9 Ensure That Partitions That Do Not Need to Be Mounted with Devices Are Mounted Using nodev (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.9 Ensure That Partitions That Do Not Need to Be Mounted with Devices Are Mounted Using nodev (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.9 Ensure That Partitions That Do Not Need to Be Mounted with Devices Are Mounted Using nodev (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.9 Ensure That Partitions That Do Not Need to Be Mounted with Devices Are Mounted Using nodev (Requirement)");

  script_tag(name:"summary", value:"The nodev option specifies that the file system cannot contain
device files. It is used to reduce the attack surface and improve security. If a directory is
mounted with the nodev option, all device files, such as files of block devices and character
devices in the directory, are parsed as common files. The system no longer considers them as device
files. If the nodev option is not used, security risks may occur. For example, an attacker creates
a file system on a USB flash drive and creates a block device file in the file system. The block
device actually points to a drive or partition such as /dev/sda on the server. If the attacker
inserts the USB flash drive into the server and the server loads the file system on the USB flash
drive, the attacker can access the corresponding drive data through the block device file. No
matter it is for a USB flash drive, a drive, or a partition, as long as maliciously device files
exist, attacks can be launched.

By default, the following directories are mounted with nodev in openEuler: /sys, /proc,
/sys/kernel/security, /dev/shm, /run, /sys/fs/cgroup, /sys/fs/cgroup/systemd, /sys/fs/pstore,
/sys/fs/bpf, /sys/fs/cgroup/files, /sys/fs/cgroup/net_cls, net_prio, /sys/fs/cgroup/devices,
/sys/fs/cgroup/freezer, /sys/fs/cgroup/cpu, cpuacct, /sys/fs/cgroup/perf_event,
/sys/fs/cgroup/pids, /sys/fs/cgroup/hugetlb, /sys/fs/cgroup/memory, /sys/fs/cgroup/blkio,
/sys/fs/cgroup/cpuset, /sys/fs/cgroup/rdma, /sys/kernel/config, /sys/kernel/debug, /dev/mqueue,
/tmp, and /run/user/0.

By default, the following directories are not mounted with nodev in openEuler (some directories
vary depending on drive partitions and deployment platforms): /dev, /dev/pts, /, /sys/fs/selinux,
/proc/sys/fs/binfmt_misc, /dev/hugepages, /boot, /var/lib/nfs/rpc_pipefs, /boot/efi, and /home.

In actual scenarios, mount partitions that do not need to be mounted with devices using the nodev
option based on service requirements.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Partitions That Do Not Need to Be Mounted with Devices Are Mounted Using nodev";

solution = "1. Unmount the mount point and mount it again using nodev.

# umount /root/nodev
# mount -o nodev /dev/vda /root/nodev/

2. If a drive or partition is mounted using the /etc/fstab configuration file, modify the file to
add the nodev mounting mode to the specified mount point.

# vim /etc/fstab
/dev/vda /root/nodev ext4 nodev 0 0";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# mount | grep -v "nodev" | awk \'{print \\$3}\' | grep -vE "^(/dev|/dev/pts|/|/sys/fs/selinux|/proc/sys/fs/binfmt_misc|/dev/hugepages|/boot|/var/lib/nfs/rpc_pipefs|/boot/efi|/home)$"';

expected_value = 'The output should be empty';

# ------------------------------------------------------------------
# CONNECTION CHECK
# ------------------------------------------------------------------

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){

  report_ssh_error(title: title,
                   solution: solution,
                   action: action,
                   expected_value: expected_value,
                   check_type: check_type);
  exit(0);
}

# ------------------------------------------------------------------
# CHECK : Verify command mount | grep -v "nodev" | awk \'{print \\$3}\' | grep -vE "^(/dev|/dev/pts|/|/sys/fs/selinux|/proc/sys/fs/binfmt_misc|/dev/hugepages|/boot|/var/lib/nfs/rpc_pipefs|/boot/efi|/home)$"
# ------------------------------------------------------------------

step_cmd = 'mount | grep -v "nodev" | awk \'{print \\$3}\' | grep -vE "^(/dev|/dev/pts|/|/sys/fs/selinux|/proc/sys/fs/binfmt_misc|/dev/hugepages|/boot|/var/lib/nfs/rpc_pipefs|/boot/efi|/home)$"';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(!actual_value){
  compliant = "yes";
  comment = "Check passed";
}else{
  compliant = "no";
  comment = "Check failed";
}

# ------------------------------------------------------------------
# REPORT
# ------------------------------------------------------------------

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);