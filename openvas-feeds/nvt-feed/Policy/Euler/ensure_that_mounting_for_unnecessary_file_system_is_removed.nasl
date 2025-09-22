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
  script_oid("1.3.6.1.4.1.25623.1.0.130424");
  script_version("2025-09-03T05:38:18+0000");
  script_tag(name:"last_modification", value:"2025-09-03 05:38:18 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Mounting for Unnecessary File System Is Removed");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.7 Ensure That Mounting for Unnecessary File System Is Removed (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.7 Ensure That Mounting for Unnecessary File System Is Removed (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.7 Ensure That Mounting for Unnecessary File System Is Removed (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.7 Ensure That Mounting for Unnecessary File System Is Removed (Requirement)");

  script_tag(name:"summary", value:"Linux supports multiple file systems through kernel objects
loaded to the kernel. As a universal OS platform, openEuler provides various kernel object files in
the /lib/modules/(kernel version)/kernel/fs/ directory to support different file systems. You can
run the insmod or modprobe command to load the kernel objects. Disabling mount for unnecessary file
systems can reduce the attack surface and prevent attacks by exploiting the vulnerabilities of
uncommon file systems.

Determine which file systems do not need to be supported based on the actual scenario and disable
mounting for these file systems through configuration. The following file systems are not commonly
used:

#cramfs, freevxfs, JFFS2, HFS, HFS Plus, SquashFS, UDF, VFAT, FAT, MS-DOS, NFS, CephFS, FUSE,
OverlayFS, and XFS");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That Mounting for Unnecessary File System Is Removed";

solution = 'If a mounted file system (cramfs in the example) does not need to be supported in the
actual scenario, run the following command to remove it:

# modprobe -r cramfs

In the /etc/modprobe.d/ directory, add a configuration file with any file name with the suffix
".conf". The owner and owner group of the configuration file are both root, and the permission is
600. Open the file and selectively add the following configurations to disable mount for file
systems that are not applicable in the current scenario.

# vim /etc/modprobe.d/test.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install fat /bin/true
install msdos /bin/true
install nfs /bin/true
install ceph /bin/true
install fuse /bin/true
install overlay /bin/true
install xfs /bin/true';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# modprobe -n -v cramfs | grep -E "(cramfs|install)"

2. Run the command in the terminal:
# lsmod | grep -E "cramfs|freevxfs|JFFS2|HFS Plus|HFS|SquashFS|UDF|VFAT|FAT|MS-DOS|NFS|CephFS|FUSE|OverlayFS|XFS"';

expected_value = '1. The output should be equal to "install /bin/true"
2. The output should be empty';

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
# CHECK 1 :  Verify command "modprobe -n -v cramfs | grep -E "(cramfs|install)"
# ------------------------------------------------------------------

step_cmd_check_1 = 'modprobe -n -v cramfs | grep -E "(cramfs|install)"';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(step_res_check_1 == 'install /bin/true'){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Verify command `lsmod | grep cramfs`
# ------------------------------------------------------------------

step_cmd_check_2 = 'lsmod | grep -E "cramfs|freevxfs|JFFS2|HFS Plus|HFS|SquashFS|UDF|VFAT|FAT|MS-DOS|NFS|CephFS|FUSE|OverlayFS|XFS"';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(!step_res_check_2){
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
