# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freepbx:freepbx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112668");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-11-22 10:00:12 +0000 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-19006");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX < 15.0.16.27, 14.0.13.12 or 13.0.197.14 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_freepbx_http_detect.nasl");
  script_mandatory_keys("freepbx/detected");

  script_tag(name:"summary", value:"FreePBX is prone to a remote admin authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability allows unauthorized users to bypass password
  authentication and access services provided by the FreePBX admin.");

  script_tag(name:"affected", value:"FreePBX versions 15.0.16.26 and below, 14.0.13.11 and below,
  13.0.197.13 and below.");

  script_tag(name:"solution", value:"Update to version 13.0.197.14, 14.0.13.12, 15.6.16.27 or
  later.");

  script_xref(name:"URL", value:"https://wiki.freepbx.org/display/FOP/2018-09-11+Core+Stored+XS://wiki.freepbx.org/display/FOP/2019-11-20+Remote+Admin+Authentication+Bypass");
  script_xref(name:"URL", value:"https://community.freepbx.org/t/freepbx-security-vulnerability-sec-2019-001/62772");

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

if (version_is_less(version: version, test_version: "13.0.197.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.0.197.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14", test_version2: "14.0.13.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.13.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "15", test_version2: "15.0.16.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.0.16.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
