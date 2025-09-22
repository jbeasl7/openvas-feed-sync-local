# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104447");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2022-11-30 11:53:10 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("vBulletin < 5.5.3 PHP Object Injection Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"vBulletin is prone to a PHP object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"vBulletin versions prior to 5.5.3.");

  script_tag(name:"solution", value:"According to the security researcher the vendor has fixed this
  flaw in version 5.5.3 or later.");

  script_xref(name:"URL", value:"https://karmainsecurity.com/exploiting-an-nday-vbulletin-php-object-injection");
  script_xref(name:"URL", value:"https://forum.vbulletin.com/forum/vbulletin-announcements/vbulletin-announcements_aa/4418489-vbulletin-connect-5-5-3-is-now-available-for-download");

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

if (version_is_less(version: version, test_version: "5.5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
