# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:otrs:otrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803940");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-25 18:35:59 +0530 (Wed, 25 Sep 2013)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2013-2625");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Object Link Restriction Bypass Vulnerability (OSA-2013-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_otrs_http_detect.nasl");
  script_mandatory_keys("otrs/detected");

  script_tag(name:"summary", value:"Open Ticket Request System (OTRS) is prone to a restriction
  bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error exists in object linking mechanism which fails check
  for access restrictions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated
  attacker to view objects, ticket titles, or edit links to objects.");

  script_tag(name:"affected", value:"OTRS versions 3.0.x prior to 3.0.19, 3.1.x prior to 3.1.14
  and 3.2.x prior to 3.2.4.");

  script_tag(name:"solution", value:"Update to version 3.0.19, 3.1.14, 3.2.4 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52969");
  script_xref(name:"URL", value:"http://otrs.org/advisory/OSA-2013-01-en/");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2.0", test_version2: "3.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
