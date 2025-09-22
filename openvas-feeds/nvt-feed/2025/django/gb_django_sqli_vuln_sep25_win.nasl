# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155274");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-04 03:20:32 +0000 (Thu, 04 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:P/A:N");

  script_cve_id("CVE-2025-57833");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.24, 5.0.x < 5.1.12, 5.2.x < 5.2.6 SQLi Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to an SQL injection (SQLi) vulnerability in
  FilteredRelation column aliases.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"FilteredRelation is subject to SQL injection in column aliases,
  using a suitably crafted dictionary, with dictionary expansion, as the
  **kwargs passed QuerySet.annotate() or QuerySet.alias().");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.24, 5.0.x, 5.1.x prior to
  5.1.12 and 5.2.x prior to 5.2.6.");

  script_tag(name:"solution", value:"Update to version 4.2.24, 5.1.12, 5.2.6 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/sep/03/security-releases/");
  script_xref(name:"URL", value:"https://nullsecurityx.codes/cve-2025-57833-django-sql-injection");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.24", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.1.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.12", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.2", test_version_up: "5.2.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
