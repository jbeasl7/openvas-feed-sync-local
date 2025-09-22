# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804216");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-01-08 17:10:27 +0530 (Wed, 08 Jan 2014)");
  script_name("TYPO3 Multiple Vulnerabilities (Feb 2010)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to get sensitive
information or execute arbitrary scripts.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple errors exist in the application:

  - An error exists in backend, which fails to sanitize certain user input.

  - An error exists in the frontend, which is caused by improper validation of
user-supplied input by the index.php script.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.2.12, 4.3.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 versions 4.2.11 and below, 4.3.1 and below");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38668/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38366");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2010-004");
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

if(version_is_less(version:vers, test_version:"4.2.12") ||
   version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
