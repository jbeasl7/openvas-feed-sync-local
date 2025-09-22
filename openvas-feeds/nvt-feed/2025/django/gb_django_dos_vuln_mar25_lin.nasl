# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154140");
  script_version("2025-03-07T15:40:19+0000");
  script_tag(name:"last_modification", value:"2025-03-07 15:40:19 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-07 02:50:45 +0000 (Fri, 07 Mar 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2025-26699");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.20, 5.0.x < 5.0.13, 5.1.x < 5.1.7 DoS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The django.utils.text.wrap() and wordwrap template filter are
  subject to a potential denial of service attack when used with very long strings.");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.20, 5.0.x prior to 5.0.13 and
  5.1.x prior to 5.1.7.");

  script_tag(name:"solution", value:"Update to version 4.2.20, 5.0.13, 5.1.7 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2025/mar/06/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.20", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.13", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.7", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
