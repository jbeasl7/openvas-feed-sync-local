# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:web_interface";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117228");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-02-17 09:45:29 +0000 (Wed, 17 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 18:52:00 +0000 (Fri, 26 Feb 2021)");

  script_cve_id("CVE-2020-35591", "CVE-2020-35592");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole Web Interface < 5.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"The Pi-hole Web Interface (previously AdminLTE) is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The new release contains the following security patches:

  - No CVE: Properly escape possible user-input

  - CVE-2020-35591: Regenerate session ID on successful login to prevent session fixation

  - CVE-2020-35592: Prevent javascript XSS attacks aimed to steal the session ID");

  script_tag(name:"affected", value:"Pi-hole Web Interface (previously AdminLTE) versions prior to
  5.4.");

  script_tag(name:"solution", value:"Update to version 5.4 or later.");

  script_xref(name:"URL", value:"https://discourse.pi-hole.net/t/pi-hole-ftl-v5-7-and-web-v5-4-released/44449");
  script_xref(name:"URL", value:"https://github.com/pi-hole/AdminLTE/releases/tag/v5.4");
  script_xref(name:"URL", value:"https://n4nj0.github.io/advisories/pi-hole-multiple-vulnerabilities-i/");

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

if (version_is_less(version: version, test_version: "5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
