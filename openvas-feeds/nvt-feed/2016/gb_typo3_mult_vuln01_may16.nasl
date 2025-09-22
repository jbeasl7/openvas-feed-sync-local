# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807824");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-05-20 16:46:03 +0530 (Fri, 20 May 2016)");
  script_name("TYPO3 Multiple Vulnerabilities (Feb 2016)");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - SQL Injection in dbal

  - Cross-Site Scripting in legacy form component

  - Cross-Site Scripting in form component");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  SQL injection and cross-site scripting (XSS) attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.0 through 6.2.17.");

  script_tag(name:"solution", value:"Update to version 6.2.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-001/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-003/");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-004/");

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
  report = report_fixed_ver(installed_version:vers, fixed_version:"6.2.18", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
