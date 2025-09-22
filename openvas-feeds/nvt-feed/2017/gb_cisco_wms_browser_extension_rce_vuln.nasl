# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:webex_meetings_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811240");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-6753");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-18 12:06:48 +0530 (Tue, 18 Jul 2017)");
  script_name("Cisco Webex Meetings Server Browser Extension Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"Cisco Webex Meetings Server is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a design defect in
  the browser extension.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code with the privileges of the affected browser.");

  script_tag(name:"affected", value:"Cisco Webex Meetings Server versions
  1.1 Base, 1.5 Base, 1.5.1.6, 1.5.1.131, 2.0 Base, 2.0.1.107, 2.0 MR2 through
  2.0 MR9, 2.0 MR9 Patch 1 through 2.0 MR9 Patch 3, 2.5 Base, 2.5.99.2, 2.5 MR1,
  2.5.1.5, 2.5.1.29, 2.5 MR2, 2.5 MR2 Patch 1, 2.5 MR3 through 2.5 MR5, 2.5 MR5
  Patch 1, 2.5 MR6, 2.5 MR6 Patch 1 through 2.5 MR6 Patch 4, 2.6.0, 2.6.1.39,
  2.6 MR1, 2.6 MR1 Patch 1, 2.6 MR2, 2.6 MR2 Patch 1, 2.6 MR3, 2.6 MR3 Patch 1,
  2.6 MR3 Patch 2, 2.7 Base, 2.7.1, 2.7 MR1, 2.7 MR1 Patch 1, 2.7 MR2, 2.7 MR2
  Patch 1, 2.8 Base and 2.8 prior to 2.8 Patch 3.");

  script_tag(name:"solution", value:"Update to Cisco Webex Meetings Server
  version 2.6MR3 Patch 5, 2.7MR2 Patch 9 or 2.8 Patch 3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170717-webex");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99614");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_webex_meetings_server_detect.nasl");
  script_mandatory_keys("cisco/webex/meetings_server/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

## 2.8 Patch 3 == 2.8.1.39
if(vers =~ "^2\.8")
  fix = "2.8 Patch 3";

## 2.7MR2 Patch 9 == 2.7.1.2103
else if(vers =~ "^2\.7")
  fix = "2.7MR2 Patch 9";

## 2.6MR3 Patch 5 == 2.6.1.3120
else if(version_is_less_equal(version:vers, test_version:"2.6"))
  fix = "2.6MR3 Patch 5";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
