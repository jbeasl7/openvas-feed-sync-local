# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803987");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2008-5656");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-12-26 15:31:34 +0530 (Thu, 26 Dec 2013)");
  script_name("TYPO3 Felogin System Extension Cross Site Scripting Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
script code.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in the felogin system extension which fails to sufficiently
sanitize user supplied input.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.2.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version 4.2.0 to 4.2.2");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46591");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32284");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-20081113-2");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.2")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.2.0 - 4.2.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
