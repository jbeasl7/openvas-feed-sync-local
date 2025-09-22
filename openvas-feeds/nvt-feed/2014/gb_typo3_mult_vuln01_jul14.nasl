# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804464");
  script_version("2024-02-22T05:06:55+0000");
  script_cve_id("CVE-2014-3941", "CVE-2014-3943");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-22 05:06:55 +0000 (Thu, 22 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-07-03 13:45:50 +0530 (Thu, 03 Jul 2014)");
  script_name("TYPO3 Multiple Vulnerabilities (TYPO3-CORE-SA-2014-001)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2014-001");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67625");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67626");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Failing to properly validate the HTTP host-header TYPO3 CMS is susceptible to host spoofing.

  - Failing to properly encode user input, several backend components are susceptible to Cross-Site
  Scripting, allowing authenticated editors to inject arbitrary HTML or JavaScript by crafting URL
  parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  host spoofing and cross-site scripting attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 4.5.0 through 4.5.33, 4.7.0 through 4.7.18,
  6.0.0 through 6.0.13, 6.1.0 through 6.1.8 and 6.2.0 through 6.2.2.");

  script_tag(name:"solution", value:"Update to version 4.5.34, 4.7.19, 6.0.14, 6.1.9, 6.2.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.33") ||
   version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.18") ||
   version_in_range(version:vers, test_version:"6.0.0", test_version2:"6.0.13") ||
   version_in_range(version:vers, test_version:"6.1.0", test_version2:"6.1.8") ||
   version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
