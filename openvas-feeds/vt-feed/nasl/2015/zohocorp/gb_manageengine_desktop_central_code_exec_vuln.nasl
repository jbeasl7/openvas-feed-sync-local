# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805716");
  script_version("2026-04-22T06:16:44+0000");
  script_cve_id("CVE-2014-9371");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2026-04-22 06:16:44 +0000 (Wed, 22 Apr 2026)");
  script_tag(name:"creation_date", value:"2015-07-08 18:54:23 +0530 (Wed, 08 Jul 2015)");

  script_name("ManageEngine Desktop Central MSP < 9.0.075 Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"ManageEngine Desktop Central MSP is prone to an arbitrary code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as 'NativeAppServlet' servlet does not sanitize
  user input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to execute
  arbitrary code.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central MSP before version 9.0.075.");

  script_tag(name:"solution", value:"Update to version 9.0.075 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-420/");

  script_copyright("Copyright (C) 2015 Greenbone AG");
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

vers = infos["version"];
path = infos["location"];

if (version_is_less(version:vers, test_version:"9.0.075")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "9.0.075", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
