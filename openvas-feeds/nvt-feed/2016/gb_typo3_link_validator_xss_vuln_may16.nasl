# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807827");
  script_version("2024-02-23T14:36:45+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-05-20 17:40:01 +0530 (Fri, 20 May 2016)");
  script_name("TYPO3 Link Validator Component XSS Vulnerability (TYPO3-CORE-SA-2016-002)");

  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  the link validator component which fails to sanitize content from editors.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.0 through 6.2.17 and
  7.6.0 through 7.6.2");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.18 or 7.6.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-002/");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(vers =~ "^6\.2" && version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.17")) {
  fix = "6.2.18";
  VULN = TRUE;
}

if(vers =~ "^7\.6" && version_in_range(version:vers, test_version:"7.6.0", test_version2:"7.6.2")) {
  fix = "7.6.3";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
