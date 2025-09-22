# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143347");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-01-13 05:38:34 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 19:40:00 +0000 (Tue, 10 Nov 2020)");

  script_cve_id("CVE-2020-5504");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.4, 5.x < 5.0.1 SQL Injection Vulnerability (PMASA-2020-1) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An SQL injection flaw has been discovered in the user accounts page.");

  script_tag(name:"impact", value:"A malicious user could inject custom SQL in place of their own username
  when creating queries to this page. An attacker must have a valid MySQL account to access the server.");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.4 and 5.x prior to 5.0.1.");

  script_tag(name:"solution", value:"Update to version 4.9.4, 5.0.1 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2020-1/");

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

if (version_is_less(version: version, test_version: "4.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^5\." && version_is_less(version: version, test_version: "5.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
