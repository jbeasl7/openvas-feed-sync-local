# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807826");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-05-20 17:17:16 +0530 (Fri, 20 May 2016)");
  script_name("TYPO3 Multiple Vulnerabilities-03 (May 2016)");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in some backend components which fail to properly encode user input.

  - An error in the default authentication service which misses to invalidate
    empty strings as password.

  - The workspace/version preview link created by a privileged (backend) user
    could be abused to obtain certain editing permission.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct authentication bypass, XSS and privilege escalation
  attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.x before 6.2.20, 7.6.x
  before 7.6.5 and 8.0.0");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.20 or 7.6.5
  or 8.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-012/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-011/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-009/");

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

if(vers =~ "^6\.2" && version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.19")) {
  fix = "6.2.20";
  VULN = TRUE;
}

else if(vers =~ "^7\.6" && version_in_range(version:vers, test_version:"7.6.0", test_version2:"7.6.4")) {
  fix = "7.6.5";
  VULN = TRUE;
}

else if(version_is_equal(version:vers, test_version:"8.0.0")) {
  fix = "8.0.1";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
