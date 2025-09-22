# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:prime_collaboration_provisioning";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106970");
  script_cve_id("CVE-2017-6755");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Prime Collaboration Provisioning Tool Web Portal Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-pcpt");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 12.1.0.692 or later.");

  script_tag(name:"summary", value:"A vulnerability in the web portal of the Cisco Prime Collaboration
Provisioning (PCP) Tool could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS)
attack against a user of the web interface of an affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of a user-supplied
value. An attacker could exploit this vulnerability by sending malicious JavaScript code to the PCP administrative
UI.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to perform actions as a
higher-level administrator.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 17:36:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-20 14:05:32 +0700 (Thu, 20 Jul 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_pcp_version.nasl");
  script_mandatory_keys("cisco_pcp/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version =~ "^12\.1\.") {
  if (version_is_less(version: version, test_version: "12.1.0.692")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.1.0.692");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
