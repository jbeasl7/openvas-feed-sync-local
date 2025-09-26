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
  script_oid("1.3.6.1.4.1.25623.1.0.130395");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That Warning Banners Contain Proper Information");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.3 Ensure That Warning Banners Contain Proper Information (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.3 Ensure That Warning Banners Contain Proper Information (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.3 Ensure That Warning Banners Contain Proper Information (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 2. Secure Access: 2.3 Identity Authentication: 2.3.3 Ensure That Warning Banners Contain Proper Information (Requirement)");

  script_tag(name:"summary", value:"Warning banners contain warning information added on the system
login page. Security warnings are displayed for all users who log in to the system. The security
warnings must include information about the organization to which the system belongs, monitoring or
records of login behavior, and legal sanctions against unauthorized login or intrusion based on
service scenarios. Inappropriate security warning information may increase the risk of system
attacks or violate local laws and regulations.
Warning banners should not expose the system version as well as application server types and
functions to users to prevent attackers from obtaining system information and launching attacks.
You also need to configure file ownership correctly. Otherwise, unauthorized users may use
incorrect or misleading information to modify files.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Ensure That Warning Banners Contain Proper Information";

solution = "1. Run the vim command to modify the alert information in the /etc/motd, /etc/issue,
and /etc/issue.net files.

2. Run the chmod command to change the permissions on the /etc/motd, /etc/issue, and /etc/issue.net
files to 644.";

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
