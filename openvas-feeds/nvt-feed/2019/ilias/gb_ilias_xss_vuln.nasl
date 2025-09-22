# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142672");
  script_version("2023-11-15T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-11-15 05:05:25 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2019-07-29 05:25:33 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:44:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2019-1010237");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.2.21, 5.3.x < 5.3.12 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ILIAS prior to version 5.2.21 and 5.3.x prior to 5.3.12.");

  script_tag(name:"solution", value:"Update to version 5.2.21, 5.3.12 or later.");

  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_116867_35.html");

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

if (version_is_less(version: version, test_version: "5.2.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.3", test_version2: "5.3.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
