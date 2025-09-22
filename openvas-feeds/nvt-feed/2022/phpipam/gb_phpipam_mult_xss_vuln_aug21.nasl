# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147497");
  script_version("2023-10-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-01-21 02:52:10 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 20:16:00 +0000 (Thu, 24 Jun 2021)");

  script_cve_id("CVE-2021-35438");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM < 1.4.4 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpipam_http_detect.nasl");
  script_mandatory_keys("phpipam/detected");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-35438: XSS (reflected) in IP calculator

  - XSS in pass-change/result.php");

  script_tag(name:"affected", value:"phpIPAM version 1.4.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.4.4 or later.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/3351");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/issues/3373");
  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/releases/tag/v1.4.4");

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

if (version_is_less(version: version, test_version: "1.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
