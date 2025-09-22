# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webcalendar:webcalendar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800472");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-0636", "CVE-2010-0637", "CVE-2010-0638");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WebCalendar < 1.2.1 Multiple CSS and CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_webcalendar_http_detect.nasl");
  script_mandatory_keys("webcalendar/detected");

  script_tag(name:"summary", value:"WebCalendar is prone to multiple CSS and CSRF Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Input passed to the 'tab' parameter in 'users.php' is not properly sanitised before being
  returned to the user.

  - Input appended to the URL after 'day.php', 'month.php', and 'week.php' is not properly
  sanitised before being returned to the user.

  - The application allows users to perform certain actions via HTTP requests without performing
  any validity checks to verify the requests. This can be exploited to delete an event, ban an IP
  address from posting, or change the administrative password if a logged-in administrative user
  visits a malicious web site.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct
  cross-site scripting and request forgery attacks.");

  script_tag(name:"affected", value:"WebCalendar version 1.2.0 and prior.");

  script_tag(name:"solution", value:"Update version 1.2.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38222");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38053");
  script_xref(name:"URL", value:"http://holisticinfosec.org/content/view/133/45/");

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

if (version_is_less_equal(version: version, test_version: "1.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
