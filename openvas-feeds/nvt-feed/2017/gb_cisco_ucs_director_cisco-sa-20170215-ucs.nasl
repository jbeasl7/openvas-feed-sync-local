# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:ucs_director";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106604");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-16 15:15:33 +0700 (Thu, 16 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-3801");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco UCS Director Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("CISCO");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_cisco_ucs_director_consolidation.nasl");
  script_mandatory_keys("cisco/ucs_director/detected");

  script_tag(name:"summary", value:"A vulnerability in the web-based GUI of Cisco UCS Director could allow an
  authenticated, local attacker to execute arbitrary workflow items with just an end-user profile.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper role-based access control (RBAC) after
  the Developer Menu is enabled in Cisco UCS Director. An attacker could exploit this vulnerability by enabling
  Developer Mode for his/her user profile with an end-user profile and then adding new catalogs with arbitrary
  workflow items to his/her profile.");

  script_tag(name:"impact", value:"An exploit could allow an attacker to perform any actions defined by these
  workflow items, including actions affecting other tenants.");

  script_tag(name:"solution", value:"Update to version 6.0.1.0 or later.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170215-ucs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

affected = make_list(
  '6.0.0.0',
  '6.0.0.1');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.0.1.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
