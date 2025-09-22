# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:std42:elfinder";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.147953");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2022-04-11 03:52:35 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-13 20:30:00 +0000 (Wed, 13 Apr 2022)");

  script_cve_id("CVE-2021-43421");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("elFinder < 2.1.60 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_elfinder_detect.nasl");
  script_mandatory_keys("studio42/elfinder/detected");

  script_tag(name:"summary", value:"elFinder is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A File Upload vulnerability exists via connector.minimal.php,
  which allows a remote malicious user to upload arbitrary files and execute PHP code.");

  script_tag(name:"affected", value:"elFinder version 2.1.59 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.60 or later.");

  script_xref(name:"URL", value:"https://github.com/Studio-42/elFinder/issues/3429");

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

if (version_is_less(version: version, test_version: "2.1.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.60", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
