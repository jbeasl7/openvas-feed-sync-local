# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108058");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2016-5091");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-26 16:39:00 +0000 (Thu, 26 Jan 2017)");
  script_tag(name:"creation_date", value:"2017-01-25 13:00:00 +0100 (Wed, 25 Jan 2017)");
  script_name("TYPO3 Extbase RCE Vulnerability (TYPO3-CORE-SA-2016-013)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2016-013/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90832");

  script_tag(name:"summary", value:"TYPO3 is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Extbase request handling fails to implement a proper access check for requested
  controller/ action combinations, which makes it possible for an attacker to execute arbitrary Extbase actions by
  crafting a special request. To successfully exploit this vulnerability, an attacker must have access to at least
  one Extbase plugin or module action in a TYPO3 installation.");

  script_tag(name:"impact", value:"A remote attacker can leverage this issue to execute arbitrary
  code within the context of the application. Successful exploits will compromise the application
  and possibly the underlying system.");

  script_tag(name:"affected", value:"TYPO3 versions 4.3.0 through 6.2.23, 7.x prior to 7.6.8 and
  8.1.0 only.");

  script_tag(name:"solution", value:"Update to version 6.2.24, 7.6.8, 8.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_in_range(version: version, test_version: "4.3.0", test_version2: "6.2.23")) {
  VULN = TRUE;
  fix = "6.2.24";
}

if (version =~ "^7\." && version_is_less(version: version, test_version: "7.6.8")) {
  VULN = TRUE;
  fix = "7.6.8";
}

if (version_is_equal(version: version, test_version: "8.1.0")) {
  VULN = TRUE;
  fix = "8.1.1";
}

if (VULN) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
