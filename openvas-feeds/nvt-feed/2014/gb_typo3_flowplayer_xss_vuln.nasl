# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803996");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2011-3642", "CVE-2013-1464");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-12 16:54:00 +0000 (Wed, 12 Feb 2020)");
  script_tag(name:"creation_date", value:"2014-01-02 11:15:58 +0530 (Thu, 02 Jan 2014)");
  script_name("TYPO3 Flowplayer XSS Vulnerability (SA-2013-002)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute script code.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in the Flowplayer which fails to sufficiently
sanitize user supplied input to 'linkUrl' parameter.");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.29, 4.7.14, 6.0.8, 6.1.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to a cross-site scripting (XSS)
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version 4.5.0 to 4.5.28, 4.7.0 to 4.7.13, 6.0.0 to 6.0.7 and 6.1.0 to 6.1.2");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53529");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48651");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57848");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2013-002");
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

if(version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.28") ||
   version_in_range(version:vers, test_version:"4.7.0", test_version2:"4.7.13") ||
   version_in_range(version:vers, test_version:"6.0.0", test_version2:"6.0.7") ||
   version_in_range(version:vers, test_version:"6.1.0", test_version2:"6.1.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See advisory", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
