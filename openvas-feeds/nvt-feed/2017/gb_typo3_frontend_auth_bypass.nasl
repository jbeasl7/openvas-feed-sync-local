# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107238");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-09-08 22:06:49 +0200 (Fri, 08 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("TYPO3 Frontend Authentication Bypass Vulnerability (TYPO3-CORE-SA-2017-002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2017-002/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96501");

  script_tag(name:"summary", value:"TYPO3 is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass the authentication
  mechanism and obtain sensitive information. This may aid in further attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 8.2.0 through 8.6.0.");

  script_tag(name:"solution", value:"Update to version 8.6.1 or later.");

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

if (version_in_range(version: version, test_version: "8.2.0", test_version2: "8.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
