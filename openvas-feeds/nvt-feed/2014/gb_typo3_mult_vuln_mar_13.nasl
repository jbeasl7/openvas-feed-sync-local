# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804203");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2013-1842", "CVE-2013-1843");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-01-03 15:01:59 +0530 (Fri, 03 Jan 2014)");
  script_name("TYPO3 Multiple Vulnerabilities (Mar 2013)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to get sensitive
  information or execute SQL commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist in the application:

  - An error exists in Extbase Framework, which fails to sanitize user input properly.

  - An error exists in the access tracking mechanism, which fails o validate user provided input.");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.24, 4.6.17, 4.7.9 or 6.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"affected", value:"TYPO3 version 4.5.0 up to 4.5.23, 4.6.0 up to 4.6.16, 4.7.0 up to 4.7.8 and
  6.0.0 up to 6.0.2");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60312");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2013-001");
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

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.23") ||
   version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.16") ||
   version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.8") ||
   version_in_range(version:vers, test_version:"6.0.0", test_version2:"6.0.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
