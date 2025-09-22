# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808270");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-07-27 10:28:48 +0530 (Wed, 27 Jul 2016)");
  script_name("TYPO3 Multiple Vulnerabilities-01 (Jul 2016)");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient validation of user supplied input by some backend components.

  - An improper unserialization of data by Import/Export component.

  - The TYPO3 backend module stores the username of an authenticated backend
    user in its cache files.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct XSS attacks and to get sensitive information
  like valid backend usernames.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.0 to 6.2.25,
  7.6.0 to 7.6.9 and 8.0.0 to 8.2.0");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.26 or
  7.6.10 or 8.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-014/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-015/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-017/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-018/");

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

if(vers =~ "^6\.2" && version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.25")) {
  fix = "6.2.26";
  VULN = TRUE;
}

else if(vers =~ "^7\.6" && version_in_range(version:vers, test_version:"7.6.0", test_version2:"7.6.9")) {
  fix = "7.6.10";
  VULN = TRUE;
}

else if(vers =~ "^8\." && version_in_range(version:vers, test_version:"8.0", test_version2:"8.2.0")) {
  fix = "8.2.1";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
