# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153598");
  script_version("2024-12-10T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-12-10 05:05:39 +0000 (Tue, 10 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-12-09 08:09:43 +0000 (Mon, 09 Dec 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-53907", "CVE-2024-53908");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.17, 5.0.x < 5.0.10, 5.1.x < 5.1.4 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-53907: Potential denial of service in django.utils.html.strip_tags())

  - CVE-2024-53908: Potential SQL injection in HasKey(lhs, rhs) on Oracle");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.17, 5.0.x prior to 5.0.10 and
  5.1.x prior to 5.1.4.");

  script_tag(name:"solution", value:"Update to version 4.2.17, 5.0.10, 5.1.4 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2024/dec/04/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.17", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.1", test_version_up: "5.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
