# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807741");
  script_version("2026-04-22T06:16:44+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2026-04-22 06:16:44 +0000 (Wed, 22 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-04-19 12:07:40 +0530 (Tue, 19 Apr 2016)");

  script_name("ManageEngine Desktop Central <= 9.1.099 Reflected XSS Vulnerability");

  script_tag(name:"summary", value:"ManageEngine Desktop Central is prone to a reflected cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as input passed via 'To' parameter of
  'Specify Delivery Format' is not validated properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause cross site
  scripting and steal the cookie of other active sessions.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central version 9.1.099 and prior.");

  script_tag(name:"solution", value:"Update to version 9.2.026 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136463");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_desktop_central_http_detect.nasl");
  script_mandatory_keys("manageengine/desktop_central/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE ))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version:version, test_version:"9.1.099")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"9.2.026", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
