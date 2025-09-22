# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112837");
  script_version("2023-11-15T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-11-15 05:05:25 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2020-11-11 09:13:11 +0000 (Wed, 11 Nov 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-18 18:29:00 +0000 (Wed, 18 Nov 2020)");

  script_cve_id("CVE-2020-25267", "CVE-2020-25268");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-25267: Authenticated stored cross-site scripting (XSS)

  - CVE-2020-25268: Authenticated remote code execution");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  gain code execution or inject arbitrary script code into an affected site.");

  script_tag(name:"affected", value:"ILIAS through version 6.4.");

  script_tag(name:"solution", value:"Update to version 6.5 or later.");

  script_xref(name:"URL", value:"https://medium.com/bugbountywriteup/exploiting-ilias-learning-management-system-4eda9e120620");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
