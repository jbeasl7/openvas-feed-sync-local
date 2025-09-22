# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812513");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2018-02-20 12:16:20 +0530 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 16:29:00 +0000 (Wed, 22 May 2019)");

  script_cve_id("CVE-2016-10712");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.5.32, 5.6.x < 5.6.18, 7.x < 7.0.3 Privilege Escalation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error occurs in the function stream_get_meta_data of the
  component File Upload. The manipulation as part of a Return Value leads to a privilege escalation
  vulnerability (Metadata).");

  script_tag(name:"impact", value:"Successfully exploitation will allow an attacker to update the
  'metadata' and affect on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"PHP prior to version 5.5.32, 5.6.x prior to 5.6.18 and 7.x
  prior to 7.0.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.5.32, 5.6.18, 7.0.3 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71323");
  script_xref(name:"URL", value:"https://git.php.net/?p=php-src.git;a=commit;h=6297a117d77fa3a0df2e21ca926a92c231819cd5");

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

if (version_is_less(version: version, test_version: "5.5.32")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.32", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
