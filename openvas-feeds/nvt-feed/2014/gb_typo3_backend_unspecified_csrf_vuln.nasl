# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804222");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-01-10 12:10:05 +0530 (Fri, 10 Jan 2014)");
  script_name("TYPO3 Backend Unspecified CSRF Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to perform cross-site
  scripting attacks, Web cache poisoning, and other malicious activities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in typo3 backend, which is caused by improper validation of
  user supplied input.");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site request forgery (CSRF) vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version 4.2.x to 4.2.16, 4.3.x to 4.3.9, and 4.4.x to 4.4.5");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65387");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46377");
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

if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.16") ||
   version_in_range(version:vers, test_version:"4.3.0", test_version2:"4.3.9") ||
   version_in_range(version:vers, test_version:"4.4.0", test_version2:"4.4.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
