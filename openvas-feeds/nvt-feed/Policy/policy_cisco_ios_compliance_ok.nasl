# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106432");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod", value:"98");

  script_name("Cisco IOS Compliance Check: Passes");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Policy");
  script_dependencies("Policy/policy_cisco_ios_compliance.nasl");
  script_mandatory_keys("policy/cisco_ios_compliance/passed");

  script_tag(name:"summary", value:"Lists all the Cisco IOS Compliance Policy Check which passed it.");

  exit(0);
}

passed = get_kb_item("policy/cisco_ios_compliance/passed");

if (passed) {
  passed = split(passed, keep: FALSE);

  report = max_index(passed) + " Checks passed:\n\n";

  foreach line (passed) {
    entry = split(line, sep: "||", keep: FALSE);
    report += "Title:           " + entry[0] + "\n";
    report += "Description:     " + entry[1] + "\n";
    report += "Regex Check:     " + entry[2] + "\n";
    report += "Must be present: " + entry[3] + "\n\n";
  }

  log_message(data: report, port: 0);
}

exit(0);
