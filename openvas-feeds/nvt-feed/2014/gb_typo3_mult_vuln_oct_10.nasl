# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804219");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2010-3714", "CVE-2010-3715", "CVE-2010-3716",
                "CVE-2010-3717", "CVE-2010-4068");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-01-09 15:25:39 +0530 (Thu, 09 Jan 2014)");
  script_name("TYPO3 Multiple Vulnerabilities (Oct 2010)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to get sensitive
  information or cause DoS condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist in the application:

  - An error exists in class.tslib_fe.php script, which does not properly compare
  certain hash values during access-control decisions.

  - An error exists backend and sys_action task, which fails to validate certain
  user provided input properly.

  - An error exists in Filtering API, which fails to handle large strings.");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.2.15, 4.3.7, 4.4.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 version 4.2.14 and below, 4.3.6 and below, 4.4.3 and below");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41691");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43786");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2010-020/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.14") ||
   version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.6") ||
   version_in_range(version:vers, test_version:"4.4.0", test_version2:"4.4.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
