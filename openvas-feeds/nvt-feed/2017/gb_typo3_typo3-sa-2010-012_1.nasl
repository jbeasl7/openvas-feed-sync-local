# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112112");
  script_cve_id("CVE-2010-3659", "CVE-2010-3660", "CVE-2010-3661", "CVE-2010-3662",
                "CVE-2010-3663", "CVE-2010-3664", "CVE-2010-3665", "CVE-2010-3666",
                "CVE-2010-3667", "CVE-2010-3668", "CVE-2010-3671");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-11-08 13:15:49 +0100 (Wed, 08 Nov 2017)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 17:57:00 +0000 (Fri, 08 Nov 2019)");
  script_name("TYPO3 < 4.1.14, 4.2.x < 4.2.13, 4.3.x < 4.3.4, 4.4.0 Multiple Vulnerabilities (TYPO3-SA-2010-012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-sa-2010-012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42029");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2010-3659: Multiple cross-site scripting (XSS) vulnerabilities

  - CVE-2010-3660: XSS on the backend

  - CVE-2010-3661: Open Redirection on the backend

  - CVE-2010-3662: SQL Injection on the backend

  - CVE-2010-3663: Arbitrary code execution on the backend

  - CVE-2010-3664: Information Disclosure on the backend

  - CVE-2010-3665: XSS on the Extension Manager

  - CVE-2010-3666: Insecure randomness in the uniqid function

  - CVE-2010-3667: Spam Abuse in the native form content element

  - CVE-2010-3668: Header Injection in the secure download feature jumpurl

  - CVE-2010-3671: Session fixation");

  script_tag(name:"affected", value:"TYPO3 versions prior to 4.1.14, 4.2.x prior to 4.2.13, 4.3.x
  prior to 4.3.4 and 4.4.0 only.");

  script_tag(name:"solution", value:"Update to version 4.1.14, 4.2.13, 4.3.4, 4.4.1 or later.");

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

if(version_is_less(version:vers, test_version:"4.1.14"))
  fix = "4.1.14";

else if(version_in_range_exclusive(version:vers, test_version_lo:"4.2.0", test_version_up:"4.2.13"))
  fix = "4.2.13";

else if(version_in_range_exclusive(version:vers, test_version_lo:"4.3.0", test_version_up:"4.3.4"))
  fix = "4.3.4";

else if(version_is_equal(version:vers, test_version:"4.4.0"))
  fix = "4.4.1";

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
