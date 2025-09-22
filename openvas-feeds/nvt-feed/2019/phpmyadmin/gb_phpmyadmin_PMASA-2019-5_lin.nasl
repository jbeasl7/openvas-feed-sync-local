# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143167");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-11-25 04:31:35 +0000 (Mon, 25 Nov 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 22:15:00 +0000 (Tue, 14 Jan 2020)");

  script_cve_id("CVE-2019-18622", "CVE-2019-19617");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.2 Multiple Vulnerabilities (PMASA-2019-5) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"phpMyAdmin is prone to multiple vulnerabilities:

  - SQL injection vulnerability (CVE-2019-18622)

  - Certain Git information is not escaped (CVE-2019-19617)");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.2.");

  script_tag(name:"solution", value:"Update to version 4.9.2 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2019-5/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2019/11/22/phpmyadmin-492-released/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if (version_is_less(version: version, test_version: "4.9.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
