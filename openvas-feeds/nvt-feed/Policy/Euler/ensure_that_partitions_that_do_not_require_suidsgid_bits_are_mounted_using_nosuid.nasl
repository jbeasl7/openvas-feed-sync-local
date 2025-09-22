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
  script_oid("1.3.6.1.4.1.25623.1.0.130435");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Partitions That Do Not Require SUID/SGID Bits Are Mounted Using nosuid");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"Partition", type:"entry", value:"/root/nosuid", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.12 Ensure That Partitions That Do Not Require SUID/SGID Bits Are Mounted Using nosuid (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.12 Ensure That Partitions That Do Not Require SUID/SGID Bits Are Mounted Using nosuid (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.12 Ensure That Partitions That Do Not Require SUID/SGID Bits Are Mounted Using nosuid (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.12 Ensure That Partitions That Do Not Require SUID/SGID Bits Are Mounted Using nosuid (Requirement)");

  script_tag(name:"summary", value:"After the SUID bit is set for an executable file, the user who
executes the file (not the file owner) is temporarily granted the permission of the file owner. For
example, common user test executes a program whose permission is 755 and owner is root. In this
case, if the SUID bit is not set,only the permission of the test user takes effect during the
process. The permission of the root user can take effect only after the SUID bit is set. SGID is
similar to SUID, but the former deals with file group permissions additionally. Mounting a
partition that does not require SUID/SGID bits using nosuid invalidates SUID/SGID bits on files in
the partition. This prevents privilege escalation through executable files in the partition and
thereby enhances partition security.

Plan the drives and partitions to be mounted, and use the nosuid option based on the actual
scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

partition = script_get_preference("Partition");

title = "Ensure That Partitions That Do Not Require SUID/SGID Bits Are Mounted Using nosuid";

solution = "Unmount the corresponding mount point and mount it again using nosuid.

# umount /root/nosuid
# mount -o nosuid /dev/vda /root/nosuid/

If a drive or partition is mounted using the /etc/fstab configuration file, modify the file to add
the nosuid mounting mode to the specified mount point.

# vim /etc/fstab
/dev/vda /root/nosuid ext4 nosuid 0 0";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# mount | grep "nosuid" | grep '+ partition +'';

expected_value = 'The output should not be empty';

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
# CHECK : Check nosuid and partition in mount
# ------------------------------------------------------------------

step_cmd = 'mount | grep "nosuid" | grep '+ partition +'';
actual_value = ssh_cmd(socket:sock, cmd:step_cmd, return_errors:TRUE, return_linux_errors_only:TRUE);

if(actual_value){
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
