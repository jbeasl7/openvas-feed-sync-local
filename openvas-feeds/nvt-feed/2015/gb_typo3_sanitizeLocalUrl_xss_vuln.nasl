# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805981");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2015-5956");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-08 10:03:49 +0530 (Thu, 08 Oct 2015)");
  script_name("TYPO3 'sanitizeLocalUrl' function XSS Vulnerability (SA-2015-009)");

  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the user input passed
  via 'returnUrl' and 'redirect_url' parameters to sanitizeLocalUrl function is
  not validated before returning to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote authenticated attackers to execute arbitrary HTML and script code in
  a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.x prior to 6.2.15,
  and 7.0.x prior to 7.4.0");

  script_tag(name:"solution", value:"Update to TYPO3 version 6.2.15 or 7.4.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536464/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76692");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2015-009");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.14")) {
  fix = "6.2.15";
  VULN = TRUE;
}

if(version_in_range(version:vers, test_version:"7.0.0", test_version2:"7.3.0")) {
  fix = "7.4.0";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
