# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webcalendar:webcalendar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802305");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WebCalendar < 1.2.4 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_webcalendar_http_detect.nasl");
  script_mandatory_keys("webcalendar/detected");

  script_tag(name:"summary", value:"WebCalendar is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input in various scripts, which allows attackers to execute arbitrary HTML and script code on the
  web server.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"WebCalendar version 1.2.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.4 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102785/SSCHADV2011-008.txt");

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

if (version_is_less_equal(version: version, test_version: "1.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
