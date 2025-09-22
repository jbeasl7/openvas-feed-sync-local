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
  script_oid("1.3.6.1.4.1.25623.1.0.130434");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Drive Data Should Be Managed in Partitions");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_add_preference(name:"CURRENT_MOUNTED_DIRECTORIES", type:"entry", value:"/boot|/tmp|/home|/var|/usr", id:1);
  script_add_preference(name:"PERMANENT_AUTOMOUNT_DIRECTORIES", type:"entry", value:"/boot|/tmp|/home|/var|/usr", id:2);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.18 Drive Data Should Be Managed in Partitions (Recommendation)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.18 Drive Data Should Be Managed in Partitions (Recommendation)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.18 Drive Data Should Be Managed in Partitions (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.18 Drive Data Should Be Managed in Partitions (Recommendation)");
  script_tag(name:"summary", value:"When installing the OS, plan different partitions for OS data
and service data based on the scenario. Do not store all data in the same drive or partition.
Properly planning drive partitions avoids or reduces the following risks:

1. Log files are too large and use up the space of the service drive or OS data drive.
2. The home directory of a common user is too large and uses up the space of the data drive or OS
drive.
3. The system partitions are not independent. As a result, when a drive is full, the basic services
of the OS are faulty, causing a comprehensive DoS attack.
4. It is difficult to minimize permissions and encrypt data drives.
5. If a drive is damaged, the OS or data cannot be restored.

openEuler is a general OS. By default, separate partitions /boot, /tmp, /home, and / are created.
You are advised to determine the partitions to be mounted to other directories and their sizes
based on the actual scenario.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Drive Data Should Be Managed in Partitions";

solution = 'You are advised to properly partition drives based on the actual scenario. The
suggestions are as follows:

1. You are advised to separate the /boot, /home, /tmp, /usr, and /var directories from root
directory / during OS installation and deployment, mount the directories to separate partitions,
and install OS files. The /tmp directory is typically mounted as a temporary memory file system
(tmpfs). If files in the /tmp directory do not need to be persistently stored after the system is
shut down, you do not need to specify a drive partition for /tmp. The OS automatically mounts a
tmpfs file system.
2. It is recommended that the service data directory be mounted to an independent partition,
separate drive, or drive array.
3. It is recommended that the logs dumped or saved locally be mounted to an independent partition,
separate drive, or drive array.
4. Properly allocate the space of each partition.


You can run the mount command to temporarily mount a data drive.

# mount /dev/sdb /mnt/data

You can also modify the /etc/fstab file to ensure that the data drive is automatically mounted
after the next reboot.

# echo "/dev/sdb /home/test ext4 defaults 1 1" >> /etc/fstab';

check_type = "SSH_Cmd";

current_mounted_directories = script_get_preference("CURRENT_MOUNTED_DIRECTORIES");
permanent_automount_directories = script_get_preference("PERMANENT_AUTOMOUNT_DIRECTORIES");

action = '1. Run the command in the terminal:
# df | grep -iE "'+ current_mounted_directories +'"

2. Run the command in the terminal:
# grep -iE "'+ permanent_automount_directories +'" /etc/fstab | grep -vE "^\\s*#"';

expected_value = '1. The output should not be empty
2. The output should not be empty';

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

overall_pass = FALSE;
actual_value = "";

# ------------------------------------------------------------------
# CHECK 1: Verify command `df | grep -iE "{{CURRENT_MOUNTED_DIRECTORIES}}"`
# ------------------------------------------------------------------

step_cmd_check_1 = 'df | grep -iE "' + current_mounted_directories + '"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2: Verify command `grep -iE "{{PERMANENT_AUTOMOUNT_DIRECTORIES}}" /etc/fstab | grep -vE "^\s*#"`
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -iE "' + permanent_automount_directories + '" /etc/fstab | grep -vE "^\\s*#"';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(step_res_check_2){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------

if(check_result_1 && check_result_2){
  overall_pass = TRUE;
}

if(overall_pass){
  compliant = "yes";
  comment = "All checks passed";
}else{
  compliant = "no";
  comment = "One or more checks failed";
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
