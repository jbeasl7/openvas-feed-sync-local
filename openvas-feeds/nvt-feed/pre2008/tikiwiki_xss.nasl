# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15709");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tiki Wiki CMS Groupware < 1.7.8 'tiki-error.php' XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_tikiwiki_http_detect.nasl");
  script_mandatory_keys("tiki/wiki/detected");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The remote version of this software is vulnerable to XSS
  attacks in tiki-error.php script due to a lack of user input sanitization.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware prior to version 1.7.8.");

  script_tag(name:"solution", value:"Update to version 1.7.8 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14121");

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

if (version_is_less(version: version, test_version: "1.7.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
