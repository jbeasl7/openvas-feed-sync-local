# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171435");
  script_version("2025-04-16T05:39:43+0000");
  script_tag(name:"last_modification", value:"2025-04-16 05:39:43 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-15 07:57:41 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-32461");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 21.12, 22.0 < 24.8, 25.0 < 27.2, 28.0 < 28.3 Code Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a code injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"wikiplugin_includetpl in
  lib/wiki-plugins/wikiplugin_includetpl.php mishandles input to an eval.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware prior to version 21.12, 22.0 prior to
  24.8, 25.0 prior to 27.2 and 28.0 prior to 28.3.");

  script_tag(name:"solution", value:"Update to version 21.12, 24.8, 27.2, 28.3 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/tikiwiki/tiki/-/commit/406bea4f6c379a23903ecfd55e538d90fd669ab0");
  script_xref(name:"URL", value:"https://gitlab.com/tikiwiki/tiki/-/commit/801ed912390c2aa6caf12b7b953e200f5d4bc0b1");
  script_xref(name:"URL", value:"https://gitlab.com/tikiwiki/tiki/-/commit/9ffb4ab21bd86837370666ecd6afd868f3d7877a");
  script_xref(name:"URL", value:"https://gitlab.com/tikiwiki/tiki/-/commit/be8dc1aa220fbceb07a7a5dc36416243afccd358");
  script_xref(name:"URL", value:"https://gitlab.com/tikiwiki/tiki/-/commit/f3f36c1ac702479209acfcaec5789d2fd1f996bc");
  script_xref(name:"URL", value:"https://tiki.org/article517");
  script_xref(name:"URL", value:"https://tiki.org/article518");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "21.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "22.0", test_version_up: "24.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "25.0", test_version_up: "27.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "27.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "28.0", test_version_up: "28.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "28.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
