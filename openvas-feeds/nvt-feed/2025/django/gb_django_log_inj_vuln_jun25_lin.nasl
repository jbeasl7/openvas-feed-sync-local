# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127895");
  script_version("2025-06-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-06-12 05:40:18 +0000 (Thu, 12 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-05 07:00:10 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2025-48432");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.22, 5.0.x < 5.1.10, 5.2.x < 5.2.2 Log Injection Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to a log injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Internal HTTP response logging used request.path directly,
  allowing control characters (e.g. newlines or ANSI escape sequences) to be written unescaped
  into logs. This could enable log injection or forgery, letting attackers manipulate log
  appearance or structure, especially in logs processed by external systems or viewed in
  terminals.");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.22, 5.0.x, 5.1.x prior to
  5.1.10 and 5.2.x prior to 5.2.2.");

  script_tag(name:"solution", value:"Update to version 4.2.22, 5.1.10, 5.2.2 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/jun/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.22", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
