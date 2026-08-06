# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134062");
  script_version("2026-08-05T06:26:26+0000");
  script_tag(name:"last_modification", value:"2026-08-05 06:26:26 +0000 (Wed, 05 Aug 2026)");
  script_tag(name:"creation_date", value:"2026-07-20 00:00:00 +0000 (Mon, 20 Jul 2026)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Ensure Software Repository Source Is Configured");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "compliance_os_check.nasl");
  script_mandatory_keys("Compliance/Launch", "policy/ssh/login/hce");
  script_xref(name:"Policy", value:"Huawei Cloud HCE 2.0 Security Configuration Baseline: 1.3.3 Ensure Software Repository Source Is Configured (Recommended)(Manual)");
  script_add_preference(name:"Status", type:"radio", value:"Incomplete;Not Compliant;Compliant", id:1);

  script_tag(name:"summary", value:"You need to configure the Yum source of the software repository
  to install and upgrade software packages. If the configuration source of the software repository
  is incorrect, the system may fail to install software or upgrade to a new version, for example, a
  patch.");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("policy_reporting_module.inc");

title = "Ensure Software Repository Source Is Configured";

solution = "Place the repo configuration file in the /etc/yum.repos.d/ directory. For example,
the file name is hce2.repo.
[HCE]
name=hce2
baseurl=<repo URL>
gpgkey=<repo GPGKEY URL>
enabled=1
priority=1
gpgcheck=1";

check_type = "Manual";

action = "Needs manual check";

expected_value = script_get_preference("Status", id:1);

actual_value = expected_value;

if(expected_value == "Incomplete"){
  compliant = "incomplete";
  comment = "Marked as incomplete via Policy.";
}else if(expected_value == "Compliant"){
  compliant = "yes";
  comment = "Marked as compliant via Policy after manual repository validation.";
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
