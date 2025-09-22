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
  script_oid("1.3.6.1.4.1.25623.1.0.130399");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Password Validity Is Set Correctly");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch", "ssh/login/euleros_eulerosvirtual_openeuler_hce");

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.7 Ensure That the Password Validity Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.7 Ensure That the Password Validity Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.7 Ensure That the Password Validity Is Set Correctly (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.2 Passwords: 2.2.7 Ensure That the Password Validity Is Set Correctly (Requirement)");

  script_tag(name:"summary", value:"If a password is not changed for a long time, the password is
vulnerable to brute force cracking, which compromises system security. If the password validity
period is set too short, the password needs to be changed frequently, increasing management costs.
In addition, users may fail to log in again if they have not logged in for a long time. Therefore,
you need to set the password validity period based on the actual service scenario.

A validity period must be set for a password. When a user attempts to log in to the system after
the password expires, the system displays a message indicating that the password has expired and
requires the user to change the password. If the user refuses to change the password, they will not
be able to log in to the system. The maximum validity period of a password must be 90 days or
shorter. Users should be prompted to change the passwords seven days or longer before they expire.
It is recommended that the minimum interval for changing a password be set to seven days. The
interval can be adjusted based on service scenarios.

The root user has the highest permission. If the password of the root user expires due to a long
period of non-use or you forget the password due to frequent changes, you cannot log in to the
system, which poses management risks. It is advised to determine whether to set the expiration time
for the password of the root user based on the actual service scenario. If the root user needs to
be frequently used for login, it is advised to set a short expiration time. If the root user is not
used for routinely managing other users, it is advised to set a long expiration time.

To ensure the ease of use of the community version in different scenarios, the password validity
period and the minimum interval between two password changes are not configured by default in the
openEuler distributions. Configure them as required.");

  exit(0);
}

include("policy_functions.inc");
include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure That the Password Validity Is Set Correctly";

solution = "There are two setting methods:

1. Modify the default configuration in the /etc/login.defs file. The modification takes effect for
the passwords of new users by default.

# vim /etc/login.defs
PASS_MAX_DAYS 90
PASS_MIN_DAYS 0
PASS_WARN_AGE 7

2. Change the password validity period of a specific user in the shadow file. For a new user, the
default password validity period is the same as that defined in the /etc/login.defs file, and the
corresponding value is written to the shadow file. For example:
# useradd test
# cat /etc/shadow <pipe> grep test
test:!:18599:0:90:7:35::

Each line in the shadow file records the password information of a user. The password information
is divided into nine fields by colons (:), as shown in the preceding example.
- The fourth field indicates the minimum interval between two password changes. The default value
is 0, indicating that the interval is not limited.
- The fifth field indicates the maximum validity period of a password (starting from the setting
date). The default value is 90 days. If the value is set to 99999, the password will never expire.
- The sixth field indicates the number of days in advance users are notified that their passwords
are about to expire. The default value is 7.
- The seventh field indicates the change validity period of a password. Once the password expires,
you can change the password within the period. During this period, you are forced to change the
password when logging in to the system. After this period elapses, you cannot log in. The default
value is 35 days.

Administrators can run the passwd command to modify the configuration. Set the minimum interval
between two password changes.

# passwd -n 0 test
Adjusting aging data for user test.
passwd: Success
Set the maximum validity period of a password.

# passwd -x 90 test
Adjusting aging data for user test.
passwd: Success

Set the number of days in advance users are notified that their passwords are about to expire.

# passwd -w 7 test
Adjusting aging data for user test.
passwd: Success

Set the change validity period of a password. (The default value cannot be set using
/etc/login.defs.)

# passwd -i 35 test
Adjusting aging data for user test.
passwd: Success";

check_type = "SSH_Cmd";

action = 'Run the command in the terminal:
# for user in $(awk -F: "\\$3 == 0 || \\$3 >= 1000 { print \\$1 }" /etc/passwd); do entry=$(grep "^$user:" /etc/shadow); if [ -z "$entry" ]; then echo "[FAIL] $user has no entry in /etc/shadow"; continue; fi; IFS=":" read -r name pass lastchg min max warn inactive expire reserved <<< "$entry"; if [[ "$max" =~ ^[0-9]+$ && "$warn" =~ ^[0-9]+$ ]]; then if ! { { [ "$max" -le 90 ] && [ "$warn" -ge 7 ]; } || { [ "$user" = "root" ] && [ "$max" -eq 99999 ]; }; }; then echo "[FAIL] $user does not comply (MaxDays=$max Warn=$warn MinDays=$min)"; fi; else echo "[FAIL] $user has invalid numeric values (MaxDays=$max Warn=$warn)"; fi; done';

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
# CHECK : Verify long command
# ------------------------------------------------------------------

step_cmd = 'for user in $(awk -F: "\\$3 == 0 || \\$3 >= 1000 { print \\$1 }" /etc/passwd); do entry=$(grep "^$user:" /etc/shadow); if [ -z "$entry" ]; then echo "[FAIL] $user has no entry in /etc/shadow"; continue; fi; IFS=":" read -r name pass lastchg min max warn inactive expire reserved <<< "$entry"; if [[ "$max" =~ ^[0-9]+$ && "$warn" =~ ^[0-9]+$ ]]; then if ! { { [ "$max" -le 90 ] && [ "$warn" -ge 7 ]; } || { [ "$user" = "root" ] && [ "$max" -eq 99999 ]; }; }; then echo "[FAIL] $user does not comply (MaxDays=$max Warn=$warn MinDays=$min)"; fi; else echo "[FAIL] $user has invalid numeric values (MaxDays=$max Warn=$warn)"; fi; done';
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