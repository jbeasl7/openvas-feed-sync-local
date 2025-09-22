# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143915");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-05-15 03:35:08 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-15 13:43:00 +0000 (Fri, 15 May 2020)");

  script_cve_id("CVE-2020-11064", "CVE-2020-11066", "CVE-2020-11067", "CVE-2020-11069");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 9.0.0 < 9.5.17, 10.0.0 < 10.4.2 Multiple Vulnerabilities (TYPO3-CORE-SA-2020-002, TYPO3-CORE-SA-2020-004 to TYPO3-CORE-SA-2020-006)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"TYPO3 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-11064: XSS vulnerability in Form Engine

  - CVE-2020-11066: Class destructors causing side-effects when being unserialized

  - CVE-2020-11067: Insecure deserialization in backend user settings

  - CVE-2020-11069: Backend Same-Site Request Forgery");

  script_tag(name:"affected", value:"TYPO3 versions 9.0.0 through 9.5.16 and 10.0.0 through
  10.4.1.");

  script_tag(name:"solution", value:"Update to version 9.5.17, 10.4.2 or later.");

  script_xref(name:"URL", value:"https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-43gj-mj2w-wh46");
  script_xref(name:"URL", value:"https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-2rxh-h6h9-qrqc");
  script_xref(name:"URL", value:"https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-2wj9-434x-9hvp");
  script_xref(name:"URL", value:"https://github.com/TYPO3/TYPO3.CMS/security/advisories/GHSA-pqg8-crx9-g8m4");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-002");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-004");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-005");
  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2020-006");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "9.0.0", test_version2: "9.5.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.0.0", test_version2: "10.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.4.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
