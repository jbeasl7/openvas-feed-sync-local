# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147786");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-03-14 04:08:29 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-12 04:23:00 +0000 (Sat, 12 Mar 2022)");

  script_cve_id("CVE-2022-0813");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.10, 5.x < 5.1.3 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue could allow users to cause an error that would reveal
  the path on disk where phpMyAdmin is running from. This requires the server to be running with
  display_errors on, which is not the recommended setting for a production environment.");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.10 and version 5.x through
  5.1.2.");

  script_tag(name:"solution", value:"Update to version 4.9.10, 5.1.3 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2022/2/11/phpmyadmin-4910-and-513-are-released/");
  script_xref(name:"URL", value:"https://www.incibe-cert.es/en/early-warning/security-advisories/phpmyadmin-exposure-sensitive-information");

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

if (version_is_less(version: version, test_version: "4.9.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);

}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
