# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153781");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2025-01-16 03:44:13 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-56374");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.18, 5.0.x < 5.0.11, 5.1.x < 5.1.5 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability in
  IPv6 validation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Lack of upper bound limit enforcement in strings passed when
  performing IPv6 validation could lead to a potential denial-of-service attack. The undocumented
  and private functions clean_ipv6_address and is_valid_ipv6_address were vulnerable, as was the
  django.forms.GenericIPAddressField form field, which has now been updated to define a max_length
  of 39 characters.

  The django.db.models.GenericIPAddressField model field was not affected.");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.18, 5.0.x prior to 5.0.11 and
  5.1.x prior to 5.1.5.");

  script_tag(name:"solution", value:"Update to version 4.2.18, 5.0.11, 5.1.5 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/jan/14/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.18", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.11", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
