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
  script_oid("1.3.6.1.4.1.25623.1.0.130382");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Do Not Enable Login Capabilities for Users Who Are Not Meant for Direct Login");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.1 Do Not Enable Login Capabilities for Users Who Are Not Meant for Direct Login (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.1 Do Not Enable Login Capabilities for Users Who Are Not Meant for Direct Login (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.1 Do Not Enable Login Capabilities for Users Who Are Not Meant for Direct Login (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.1 Users: 2.1.1 Do Not Enable Login Capabilities for Users Who Are Not Meant for Direct Login (Requirement)");

  script_tag(name:"summary", value:"Typically, a Linux system has multiple users, not all of which
are used for login. For instance, some users are automatically created during the installation of
software packages like systemd and dhcp. These users serve specific purposes, such as running
related software services. It is essential not to enable login capabilities for users who are not
meant for direct login. Otherwise, the attack surface increases, allowing attackers to log in using
these users and execute commands in Bash.

Note that sync, shutdown, and halt users are special users and cannot have their shell set to
nologin or false. The passwords of these users are set to * in the /shadow file, preventing direct
login.

By default, users who are not meant for direct login do not have the login capabilities in
openEuler.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Do Not Enable Login Capabilities for Users Who Are Not Meant for Direct Login";

solution = "You can lock and unlock a user in either of the following ways:

1. Run the usermod command to modify the /etc/passwd file and set the login shell of a specified
user to /sbin/nologin or /bin/false. This not only prevents user login, but also prevents switching
to a specified user using the su command. Therefore, this method is recommended. Specific
operations are as follows (test is the user name):

Lock:
# usermod -s /sbin/nologin test

Or

# usermod -s /bin/false test

Unlock:
# usermod -s /bin/bash test

2. Open the /etc/shadow file. Add an exclamation mark (!) or !! to the second field of the
specified user to lock the password. You can run the following command to implement the operation
(test is the user name. If no password is set for the user, the system displays a message
indicating that the operation fails):

Lock:
# usermod -L test

Or

# passwd -l test

Unlock:
# usermod -U test

Or

# passwd -u test

If a password is locked by running the usermod command, you can run the passwd command to unlock
the password, and vice versa. After the password is locked or unlocked, you can run the following
command to check the status. LK, NP, and PS indicate that the password is locked, not set, and set
and unlocked, respectively.

# passwd -S test
test LK 2022-01-01 0 30 10 35 (Password locked.)

Or

# passwd -S test
test NP 2020-12-03 0 50 10 35 (Empty password.)

Or

# passwd -S test
test PS 2022-01-01 0 30 10 35 (Password set, SHA512 crypt.)";

check_type = "Manual";

action = "Needs manual check";

expected_value = script_get_preference("Status", id:1);

actual_value = expected_value;

# ------------------------------------------------------------------
# MANUAL CHECK
# ------------------------------------------------------------------

if(expected_value == "Compliant"){
  compliant = "yes";
  comment = "Marked as Compliant via Policy";
}
else if(expected_value == "Not Compliant"){
  compliant = "no";
  comment = "Marked as Non-Compliant via Policy.";
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
