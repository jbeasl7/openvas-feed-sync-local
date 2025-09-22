# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106891");
  script_cve_id("CVE-2017-6716");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Firepower Management Center Stored Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170621-fmc2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web framework code of Cisco Firepower Management
  Center could allow an authenticated, remote attacker to conduct a stored cross-site scripting (XSS) attack
  against a user of the web interface of an affected system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of some parameters
  passed to the web server. An attacker could exploit this vulnerability by convincing a user to access a malicious
  link or by intercepting a user request and injecting malicious code into the request.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary script code in the
  context of the affected site or allow the attacker to access sensitive browser-based information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-07 17:38:00 +0000 (Fri, 07 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-06-22 10:09:05 +0700 (Thu, 22 Jun 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_firepower_management_center_consolidation.nasl");
  script_mandatory_keys("cisco/firepower_management_center/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

affected = make_list(
  '5.3.1.7',
  '5.4.0',
  '5.4.0.2',
  '5.4.1',
  '5.4.1.1',
  '5.4.1.2',
  '5.4.1.3',
  '5.4.1.4',
  '5.4.1.5',
  '5.4.1.6',
  '5.4.1.9');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
