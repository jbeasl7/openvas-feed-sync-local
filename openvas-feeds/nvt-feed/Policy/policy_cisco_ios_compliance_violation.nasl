# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106433");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-11 10:55:08 +0700 (Wed, 11 Jan 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod", value:"98");
  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Cisco IOS Compliance Check: Failed");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Policy");
  script_dependencies("Policy/policy_cisco_ios_compliance.nasl");
  script_mandatory_keys("policy/cisco_ios_compliance/failed");

  script_tag(name:"summary", value:"Lists all the Cisco IOS Compliance Policy Checks which did NOT pass.");

  script_tag(name:"solution", value:"Update or reconfigure the affected service / system / host according to the
  policy requirement.");

  exit(0);
}

failed = get_kb_item("policy/cisco_ios_compliance/failed");

if (failed) {
  failed = split(failed, keep: FALSE);

  report = max_index(failed) + " Checks failed:\n\n";

  foreach line (failed) {
    entry = split(line, sep: "||", keep: FALSE);
    report += "Title:       " + entry[0] + "\n";
    report += "Description: " + entry[1] + "\n";
    report += "Solution:    " + entry[2] + "\n";
    if (max_index(entry) == 4)
      report += "Remediation: " + entry[3] + "\n";
    report += '\n';
  }

  security_message( port:0, data:report );
}

exit(0);
