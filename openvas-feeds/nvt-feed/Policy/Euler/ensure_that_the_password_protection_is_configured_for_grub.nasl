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
  script_oid("1.3.6.1.4.1.25623.1.0.130405");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Password Protection Is Configured for GRUB");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.9 Ensure That the Password Protection Is Configured for GRUB (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.9 Ensure That the Password Protection Is Configured for GRUB (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.9 Ensure That the Password Protection Is Configured for GRUB (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.9 Ensure That the Password Protection Is Configured for GRUB (Requirement)");

  script_tag(name:"summary", value:"GRUB is the default bootloader of Linux. The bootloader can set
the startup mode of the system. By setting the GRUB password, you can prevent attackers from
modifying the GRUB setting to enter the single-user mode.

If the GRUB password is not set, attackers can easily access the GRUB editing menu and modify boot
parameters to launch attacks. For example, attackers can enter the single-user mode to change the
password of the root user and steal data.

UEFI and legacy are two different boot modes, and the corresponding GRUB configuration file paths
are different. The UEFI and legacy configuration paths are /boot/efi/EFI/openEuler and /boot/grub2,
respectively.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Password Protection Is Configured for GRUB";

solution = '1. During openEuler installation, the GRUB2 password is manually set on the GUI.

2. You are advised to change the password upon the first login and periodically update the
password. If the password is disclosed, startup options may be tampered with, causing system
startup faults.

Enter grub2-mkpasswd-pbkdf2 on the endpoint and enter a cleartext password as prompted to generate
a password ciphertext encrypted using SHA512. xxxx indicates the ciphertext.

# grub2-mkpasswd-pbkdf2
Enter password:
Reenter password:
PBKDF2 hash of your password is
grub.pbkdf2.sha512.10000.xxxx

In UEFI mode, run the following command to export the new password ciphertext to the
/boot/efi/EFI/openEuler/user.cfg file:

# echo "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.xxxx" > /boot/efi/EFI/openEuler/user.cfg

In legacy mode, run the following command to export the new password ciphertext to the
/boot/grub2/user.cfg file:

# echo "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.xxxx" > /boot/grub2/user.cfg

3. When the system restarts next time, if you need to enter the GRUB2 menu, you must enter the new
password.';

check_type = "SSH_Cmd";

action = '1. Run the command in the terminal:
# grep -i "password_pbkdf2" /boot/efi/EFI/openEuler/grub.cfg /boot/grub2/grub.cfg 2>/dev/null

2. Run the command in the terminal:
# grep -i "grub.pbkdf2.sha512.10000" /boot/efi/EFI/openEuler/grub.cfg /boot/grub2/grub.cfg 2>/dev/null

3. Run the command in the terminal:
# awk -F"=" "/^GRUB2_PASSWORD=/ {print \\$2}" /boot/efi/EFI/openEuler/user.cfg /boot/grub2/user.cfg 2>/dev/null';

expected_value = '1. The output should contain "password_pbkdf2"
2. The output should contain "grub.pbkdf2.sha512.10000."
3. The output should contain "grub.pbkdf2.sha512.10000."';

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
# CHECK 1 :  Check password_pbkdf2 directive (grub.cfg)
# ------------------------------------------------------------------

step_cmd_check_1 = 'grep -i "password_pbkdf2" /boot/efi/EFI/openEuler/grub.cfg /boot/grub2/grub.cfg 2>/dev/null';
step_res_check_1 = ssh_cmd(socket:sock, cmd:step_cmd_check_1, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '1. ' + step_res_check_1 + '\n';
check_result_1 = FALSE;

if(strstr(step_res_check_1, 'password_pbkdf2')){
  check_result_1 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 2 :  Check PBKDF2 hash reference inside grub.cfg
# ------------------------------------------------------------------

step_cmd_check_2 = 'grep -i "grub.pbkdf2.sha512.10000" /boot/efi/EFI/openEuler/grub.cfg /boot/grub2/grub.cfg 2>/dev/null';
step_res_check_2 = ssh_cmd(socket:sock, cmd:step_cmd_check_2, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '2. ' + step_res_check_2 + '\n';
check_result_2 = FALSE;

if(strstr(step_res_check_2, 'grub.pbkdf2.sha512.10000.')){
  check_result_2 = TRUE;
}

# ------------------------------------------------------------------
# CHECK 3 :  Check GRUB2 password hash (user.cfg)
# ------------------------------------------------------------------

step_cmd_check_3 = 'awk -F"=" "/^GRUB2_PASSWORD=/ {print \\$2}" /boot/efi/EFI/openEuler/user.cfg /boot/grub2/user.cfg 2>/dev/null';
step_res_check_3 = ssh_cmd(socket:sock, cmd:step_cmd_check_3, return_errors:TRUE, return_linux_errors_only:TRUE);
actual_value += '3. ' + step_res_check_3 + '\n';
check_result_3 = FALSE;

if(strstr(step_res_check_3, 'grub.pbkdf2.sha512.10000.')){
  check_result_3 = TRUE;
}

# ------------------------------------------------------------------
# FINAL RESULT
# ------------------------------------------------------------------
if(check_result_1 && check_result_2 && check_result_3){
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
