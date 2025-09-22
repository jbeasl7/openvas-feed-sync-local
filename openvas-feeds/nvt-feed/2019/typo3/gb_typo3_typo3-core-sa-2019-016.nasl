# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112602");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2019-07-11 13:53:11 +0200 (Thu, 11 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-12 14:15:00 +0000 (Fri, 12 Jul 2019)");

  script_cve_id("CVE-2019-10912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 9.4.x <= 9.5.7 Insecure Deserialization Vulnerability in Third Party Component");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"It has been discovered that a third party dependency used by TYPO3
  is susceptible of being used during insecure deserialization.");

  script_tag(name:"insight", value:"Issues within the third party component symfony/cache could have been potentially leading
  to removal of arbitrary files in combination with other insecure deserialization vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"TYPO3 versions 9.4.0 through 9.5.7.");

  script_tag(name:"solution", value:"Update to version 9.5.8 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2019-016/");
  script_xref(name:"URL", value:"https://symfony.com/blog/cve-2019-10912-prevent-destructors-with-side-effects-from-being-unserialized");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_in_range(version: version, test_version: "9.4.0", test_version2: "9.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.8", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
