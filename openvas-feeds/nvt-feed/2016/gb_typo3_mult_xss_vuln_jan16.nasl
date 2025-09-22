# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806665");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2015-8759", "CVE-2015-8758", "CVE-2015-8757", "CVE-2015-8755");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-12 02:59:00 +0000 (Tue, 12 Jan 2016)");
  script_tag(name:"creation_date", value:"2016-01-19 12:41:21 +0530 (Tue, 19 Jan 2016)");
  script_name("TYPO3 Multiple Cross-Site Scripting Vulnerabilities (Jan 2016)");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in authorized editors which can insert javascript commands by using
  the url scheme 'javascript:'.

  - An error in editor where input passed to editor is not properly encoded.

  - An error while HTML encode extension data during an extension installation.

  - An error while encoding user input.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary script code in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.x before 6.2.16 and 7.x
  before 7.6.1");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.16 or 7.6.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2015-011");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79250");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79254");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/79236");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2015-010");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2015-013");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2015-012");

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

if(vers =~ "^6\.2" && version_in_range(version:vers, test_version:"6.2.0", test_version2:"6.2.15")) {
  fix = "6.2.16";
  VULN = TRUE;
}

if(vers =~ "^7\." && version_in_range(version:vers, test_version:"7.0", test_version2:"7.6.0")) {
  fix = "7.6.1";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
