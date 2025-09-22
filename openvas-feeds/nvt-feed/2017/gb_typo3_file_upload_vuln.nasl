# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112040");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2017-14251");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-09-12 07:56:49 +0200 (Tue, 12 Sep 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-04 02:29:00 +0000 (Mon, 04 Dec 2017)");
  script_name("TYPO3 Unrestricted File Upload Vulnerability (TYPO3-CORE-SA-2017-007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2017-007/");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1039295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100620");

  script_tag(name:"summary", value:"TYPO3 is prone to an unrestricted file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability occurs in the fileDenyPattern in
  sysext/core/Classes/Core/SystemEnvironmentBuilder.php.");

  script_tag(name:"impact", value:"Remotely authenticated users may upload files with a .pht
  extension and may consequently execute arbitrary PHP code.");

  script_tag(name:"affected", value:"TYPO3 versions 7.6.0 through 7.6.21 and 8.0.0 through 8.7.4.");

  script_tag(name:"solution", value:"- Update to version 7.6.22, 8.7.5 or later

  - Make sure overridden settings for TYPO3_CONF_VARS/BE/fileDenyPattern are adjusted");

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

if (version =~ "^7\." && version_in_range(version: version, test_version: "7.6.0", test_version2: "7.6.21")) {
  fix = "7.6.22";
  VULN = TRUE;
}

if (version =~ "^8\." && version_in_range(version: version, test_version: "8.0.0", test_version2: "8.7.4")) {
  fix = "8.7.5";
  VULN = TRUE;
}

if (VULN) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
