# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803997");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2012-1605");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-01-02 12:00:45 +0530 (Thu, 02 Jan 2014)");
  script_name("TYPO3 Extbase HMAC Unserialization Weakness");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to unserialize arbitrary
objects and possibly execute arbitrary script code.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An error exists in Extbase Framework which has issue related to missing HMAC
signature for a request argument");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.6.7 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"TYPO3 is prone to Unserialization Weakness.");
  script_tag(name:"affected", value:"TYPO3 version 4.6.0 up to 4.6.6");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/03/30/4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52771");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2012-001");
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

if(version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.6")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.6.0 - 4.6.6", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
