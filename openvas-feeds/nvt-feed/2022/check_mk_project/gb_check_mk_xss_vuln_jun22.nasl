# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:checkmk:checkmk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127051");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2022-06-20 13:35:03 +0000 (Mon, 20 Jun 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 20:58:00 +0000 (Fri, 21 Jan 2022)");

  script_cve_id("CVE-2020-28919");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Check MK 1.6.0x < 1.6.0p19 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_checkmk_server_http_detect.nasl");
  script_mandatory_keys("checkmk/server/detected");

  script_tag(name:"summary", value:"Check MK is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Authenticated users that are allowed to configure and share
  custom views could inject arbitrary JS code to all users which are permitted to view this
  view.");

  script_tag(name:"affected", value:"Check MK version 1.6.0x through 1.6.0p18.");

  script_tag(name:"solution", value:"Update to version 1.6.0p19 or later.");

  script_xref(name:"URL", value:"https://checkmk.com/check_mk-werks.php?werk_id=11501");
  script_xref(name:"URL", value:"https://emacsninja.com/posts/cve-2020-28919-stored-xss-in-checkmk-160p18.html");

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

if (version_in_range(version: version, test_version: "1.6.0", test_version2: "1.6.0p18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.0p19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
