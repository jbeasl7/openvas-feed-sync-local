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
  script_oid("1.3.6.1.4.1.25623.1.0.130429");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:56 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.15 Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured (Requirement)");

  script_tag(name:"summary", value:"The number of files that can be opened in Linux is limited.
Once the limit is reached by a user, other users can no longer open files.
By default, openEuler limits the maximum number of file handles that can be opened by each user to
1024. If the value exceeds 1024, new file handles cannot be opened. Users can change the limit for
the current session to a value no more than the hard limit set by the administrator (524288 by
default). The root user can change the limit to any value. The limit should be set properly based
on services to prevent a user from opening too many file handles and exhausting system resources.
You can run the ulimit command with the following options to set the limit:

1. Hn: Checks or sets the maximum value of the limit. In a common user session, the limit can only
be lowered once it is set. For example, if the value is set to 3000 (no more than the maximum value
524288 set by the administrator), the limit can only be set to a value less than or equal to 3000
later.

2. -Sn: Checks or sets the current limit. The value is used to limit the number of opened handles.
The limit can be increased or decreased, but cannot exceed the limit specified by -Hn.

Common users can set the limit only for the current session.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Ensure That the Number of Files That Can Be Opened by Users Is Correctly Configured";

solution = "1. The /etc/security/limits.conf file can be used to configure the default limit and
maximum limit for each user. For example, add the following lines:

username hard nofile 10000
username soft nofile 2000

2. Run the ulimit command to set the limit for a session.

Set the limit to 2000 as a common user:
ulimit -Sn 2000
Set the maximum value of the limit to 5000 (no more than the previous maximum value) as a common
user:
ulimit -Hn 5000
Set both the limit and the maximum value of the limit:
ulimit -n 3000

For the root user, the setting method is the same. However, the root user can set the maximum value
of the limit to a value greater than the default value 524288 in openEuler.

# ulimit -Hn 1000000
# ulimit -Hn
1000000";

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
