# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108655");
  script_version("2023-12-01T05:05:39+0000");
  script_cve_id("CVE-2019-13051");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2019-09-30 07:12:45 +0000 (Mon, 30 Sep 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-11 15:27:00 +0000 (Fri, 11 Oct 2019)");
  script_name("Pi-hole Web Interface < 4.3.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to a
  command injection and multiple stored cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The stored XSS allows authenticated users with correct
  permissions to inject arbitrary web script or HTML via various settings in the settings.php

  The command injection allows an authenticated user to execute arbitrary commands via admin email
  on the underlying server with the privileges of the local user running the service.");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) before version
  4.3.2.");

  script_tag(name:"solution", value:"Update to version 4.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/1005");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/pull/974");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/releases/tag/v4.3.2");
  script_xref(name:"URL", value:"https://pi-hole.net/2019/09/21/pi-hole-4-3-2-release-notes/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
