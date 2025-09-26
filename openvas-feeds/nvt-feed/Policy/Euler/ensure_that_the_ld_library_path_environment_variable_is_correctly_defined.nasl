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
  script_oid("1.3.6.1.4.1.25623.1.0.130427");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-05-07 11:45:55 +0000 (Wed, 07 May 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure That the LD_LIBRARY_PATH Environment Variable Is Correctly Defined");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Policy");

  script_add_preference(name:"Status", type:"radio", value:"Not Compliant;Compliant", id:1);

  script_xref(name:"Policy", value:"EulerOS Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.19 Ensure That the LD_LIBRARY_PATH Environment Variable Is Correctly Defined (Requirement)");
  script_xref(name:"Policy", value:"EulerOS Virtual: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.19 Ensure That the LD_LIBRARY_PATH Environment Variable Is Correctly Defined (Requirement)");
  script_xref(name:"Policy", value:"openEuler Baseline: Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.19 Ensure That the LD_LIBRARY_PATH Environment Variable Is Correctly Defined (Requirement)");
  script_xref(name:"Policy", value:"HCE Linux (Huawei Cloud EulerOS): Security Committee Benchmark (v1.0.0): 1. Initial deployment: 1.1 File Systems: 1.1.19 Ensure That the LD_LIBRARY_PATH Environment Variable Is Correctly Defined (Requirement)");

  script_tag(name:"summary", value:"LD_LIBRARY_PATH is an environmental variable in Linux. When
loading a dynamic link library, the program preferentially obtains the library from the path
specified by LD_LIBRARY_PATH. Generally, LD_LIBRARY_PATH should not be set, because a maliciously
set value will make the program link to an incorrect dynamic library, causing security risks.

Note: Dynamic libraries can also be configured in the /etc/ld.so.conf.d directory. Ensure that the
configurations in the directory are correct.

By default, LD_LIBRARY_PATH is not set in openEuler. If it is required in an actual scenario,
ensure that its value is correct in all user contexts.");

  exit(0);
}

include("policy_reporting_module.inc");

title = "Ensure That the LD_LIBRARY_PATH Environment Variable Is Correctly Defined";

solution = "Delete the LD_LIBRARY_PATH configuration item from all configuration files or set it
correctly.";

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
