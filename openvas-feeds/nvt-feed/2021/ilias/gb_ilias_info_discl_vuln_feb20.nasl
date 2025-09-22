# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145963");
  script_version("2023-11-15T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-11-15 05:05:25 +0000 (Wed, 15 Nov 2023)");
  script_tag(name:"creation_date", value:"2021-05-18 04:52:48 +0000 (Tue, 18 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-21 16:33:00 +0000 (Fri, 21 May 2021)");

  script_cve_id("CVE-2020-23995");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS < 5.3.19, 5.4.x < 5.4.12 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"ILIAS is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure vulnerability allows remote
  authenticated attackers to get the upload data path via a workspace upload.");

  script_tag(name:"affected", value:"ILIAS versions prior to 5.3.19 and 5.4.x prior to 5.4.12.");

  script_tag(name:"solution", value:"Update to version 5.3.19, 5.4.12 or later.");

  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_118817_35.html");
  script_xref(name:"URL", value:"https://docu.ilias.de/goto_docu_pg_122177_35.html");

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

if (version_is_less(version: version, test_version: "5.3.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.4.0", test_version2: "5.4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
