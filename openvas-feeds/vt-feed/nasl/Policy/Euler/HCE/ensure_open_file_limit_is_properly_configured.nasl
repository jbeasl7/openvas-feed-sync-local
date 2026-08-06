# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134063");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-20 00:00:00 +0000 (Mon, 20 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure Open File Limit Is Properly Configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");
  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.4.1 Ensure Open File Limit Is Properly Configured (Recommended)(Manual)");
  script_add_preference(name:"Status", type:"radio", value:"Incomplete;Not Compliant;Compliant", id:1);

  script_tag(name:"summary", value:"Linux has defined an open file limit. Once the limit is reached
  by a user, other users can no longer open files. In HCE, the limit is 1,024 by default. If more
  than 1,024 file handles have been opened, new file handles cannot be opened. Common users can
  change the limit to a value up to 524288. The root administrator can change the limit flexibly.
  The limit should be set properly based on services to prevent a user from opening too many file
  handles and exhausting system resources.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure Open File Limit Is Properly Configured";

solution = "The following parameter values are for reference. Change them according to service
requirements.
Temporary setting: use the ulimit command. Set the limit to 2000.
# ulimit -Sn 2000
Run the following command to set the maximum value of the limit to 10000. After this setting is
complete, common users can change the limit to a value up to 10000 by invoking the -Sn parameter.
# ulimit -Hn 10000
Or run the following command to set the value and the maximum value of the limit at the same time.
# ulimit -n 30000
The root user can change the maximum value of the limit beyond the default value of 524288.
# ulimit -Hn 1000000
# ulimit -Hn
1000000
Permanent setting: Open the /etc/security/limits.conf file, add the following two lines of code at
the end of the file. Set the value depends on the actual scenario. soft indicates the current
number of file handles that can be opened by a user. hard indicates the maximum number of file
handles that can be changed to. For example:
# soft nofile 32768
# hard nofile 65536";

check_type = "Manual";

action = "Needs manual check";

expected_value = script_get_preference("Status", id:1);

actual_value = expected_value;

# ------------------------------------------------------------------
# MANUAL CHECK
# ------------------------------------------------------------------

if(expected_value == "Incomplete"){
  compliant = "incomplete";
  comment = "Marked as incomplete via Policy.";
}else if(expected_value == "Compliant"){
  compliant = "yes";
  comment = "Marked as compliant via Policy after manual limit validation.";
}else if(expected_value == "Not Compliant"){
  compliant = "no";
  comment = "Marked as non-compliant via Policy.";
}

target = get_kb_item("policy/ssh/login/os-release");
comment = "Target: " + target + "\n" + comment;

report_audit(action: action,
             actual_value: actual_value,
             expected_value: expected_value,
             is_compliant: compliant,
             solution: solution,
             check_type: check_type,
             title: title,
             comment: comment);

exit(0);
