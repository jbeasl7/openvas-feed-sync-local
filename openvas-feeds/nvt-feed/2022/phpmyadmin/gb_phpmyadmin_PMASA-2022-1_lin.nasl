# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147519");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-01-27 01:54:03 +0000 (Thu, 27 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 14:24:00 +0000 (Thu, 27 Jan 2022)");

  script_cve_id("CVE-2022-23807");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin 4.9.x < 4.9.8, 5.1.x < 5.1.2 2FA Bypass Vulnerability (PMASA-2022-1) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a two factor authentication bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is a sequence of actions a valid user can take that will
  allow them to bypass two factor authentication for that account. A user must first connect to
  phpMyAdmin (presumably using their two factor authentication method) in order to prepare their
  account for the bypass.

  Note that a user is still able to disable two factor authentication through conventional means.
  This only addresses an unintentional security weakness in how phpMyAdmin processes a user's two
  factor status.");

  script_tag(name:"affected", value:"phpMyAdmin version 4.9.x prior to 4.9.8 and 5.x prior to
  5.1.2.");

  script_tag(name:"solution", value:"Update to version 4.9.8, 5.1.2 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2022-1/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.9.0", test_version_up: "4.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
