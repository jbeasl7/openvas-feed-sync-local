# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803988");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2009-0255", "CVE-2009-0256", "CVE-2009-0257", "CVE-2009-0258");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 16:10:04 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-12-26 16:32:44 +0530 (Thu, 26 Dec 2013)");
  script_name("TYPO3 Multiple Vulnerabilities (Jan 2009)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48135");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33376");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2009-001/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code or steal the victim's cookie-based authentication credentials.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:'Multiple errors exist in the application:
  - An error exists in Indexed Search Engine system extension which fails to
  validate user-supplied input properly.
  - An error exists in session tokens, which is caused by the improper validation.
  - An error exists in Workspace module which fails to validate user-supplied
  input properly.');
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.0.10, 4.1.8, 4.2.4 or later.");
  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 versions 4.0.0 to 4.0.9, 4.1.0 to 4.1.7, 4.2.0 to 4.2.3");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.9") ||
   version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.7") ||
   version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.10, 4.1.8, 4.2.4 or later", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
