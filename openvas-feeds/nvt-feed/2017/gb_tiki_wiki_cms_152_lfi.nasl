# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108064");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-01-30 16:00:00 +0100 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-14 01:59:00 +0000 (Tue, 14 Mar 2017)");

  script_cve_id("CVE-2016-10143");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 12.11, 13.x < 15.4 Local File Inclusion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a local file inclusion
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due to improper sanitization of input passed to
  the 'fixedURLData' parameter of the 'display_banner.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow an user having access to the
  admin backend to gain access to arbitrary files and to compromise the application.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware versions prior to 12.11 LTS, 13.x,
  14.x and 15.x prior to 15.4.");

  script_tag(name:"solution", value:"Update to version 12.11 LTS, 15.4 or later.");

  script_xref(name:"URL", value:"http://tiki.org/article445-Security-updates-Tiki-16-2-15-4-and-Tiki-12-11-released");
  script_xref(name:"URL", value:"https://sourceforge.net/p/tikiwiki/code/60308/");

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

if (version_is_less(version: version, test_version: "12.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13", test_version2: "15.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
