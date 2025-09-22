# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16280");
  script_version("2025-05-29T05:40:25+0000");
  script_tag(name:"last_modification", value:"2025-05-29 05:40:25 +0000 (Thu, 29 May 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"13150");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("vBulletin < 2.3.6, 3.0.x < 3.0.6 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("vbulletin_http_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"summary", value:"vBulletin is vulnerable to a cross-site scripting (XSS) issue,
  due to a failure of the application to properly sanitize user-supplied URI input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"As a result of this vulnerability, it is possible for a remote
  attacker to create a malicious link containing script code that will be executed in the browser of
  an unsuspecting user when followed.

  This may facilitate the theft of cookie-based authentication credentials as well as other
  attacks.");

  script_tag(name:"affected", value:"vBulletin versions prior to 2.3.6 and 3.0.x prior to 3.0.6.");

  script_tag(name:"solution", value:"Update to version 2.3.6, 3.0.6 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.3.6") ||
   version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.3.6/3.0.6", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
