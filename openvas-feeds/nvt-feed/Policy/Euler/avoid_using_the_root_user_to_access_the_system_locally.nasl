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
  script_oid("1.3.6.1.4.1.25623.1.0.130411");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Avoid Using the root User to Access the System Locally");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.9 Avoid Using the root User to Access the System Locally (Recommendation)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.4 Access Control: 2.4.9 Avoid Using the root User to Access the System Locally (Recommendation)");

  script_tag(name:"summary", value:"Users with the root permission can access all Linux resources.
If the root user is used to log in to the Linux OS to perform operations, there are many potential
security risks. To avoid the risks, do not use the root user to log in to the Linux OS. If
necessary, indirectly use the root user through other technical means (for example, run the sudo or
su command).

The root user has the highest permission. Therefore, logging in to the system as the root user
poses the following risks:

1. High-risk misoperations may cause server breakdown, for example, deleting or modifying key
system files by mistake.
2. If multiple users need to perform operations as the root user, the password of the root user is
kept by multiple users, which may cause password leakage and increase password maintenance costs.

By default, using the root user for local login is not configured in openEuler. If the root user is
not required for local login in actual scenarios, you are advised to disable the root user for
local login.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Avoid Using the root User to Access the System Locally";

solution = "1. Add the pam_access.so module of the user type to the /etc/pam.d/system-auth file,
and load the module before the sufficient control line.

# vim /etc/pam.d/system-auth
.
user     required      pam_unix.so
user     required      pam_faillock.so
user     required      pam_access.so
user     sufficient     pam_localuser.so
.

2. Prevent the root user from logging in to tty1 by setting the /etc/security/access.conf file.

# vim /etc/security/access.conf
-:root:tty1";

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
