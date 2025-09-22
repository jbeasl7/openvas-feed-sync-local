# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152821");
  script_version("2024-10-24T07:44:29+0000");
  script_tag(name:"last_modification", value:"2024-10-24 07:44:29 +0000 (Thu, 24 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-08-07 03:15:27 +0000 (Wed, 07 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-07 18:35:05 +0000 (Wed, 07 Aug 2024)");

  script_cve_id("CVE-2024-41989", "CVE-2024-41990", "CVE-2024-41991", "CVE-2024-42005");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 4.x < 4.2.15, 5.x < 5.0.8 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-41989: Memory exhaustion in django.utils.numberformat.floatformat()

  - CVE-2024-41990: Potential denial of service (DoS) in django.utils.html.urlize()

  - CVE-2024-41991: Potential denial of service (DoS) in django.utils.html.urlize() and
  AdminURLFieldWidget

  - CVE-2024-42005: Potential SQL injection (SQLi) in QuerySet.values() and values_list()");

  script_tag(name:"affected", value:"Django version 4.x prior to 4.2.15 and 5.x prior to 5.0.8.");

  script_tag(name:"solution", value:"Update to version 4.2.15, 5.0.8 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2024/aug/06/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.15", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.8", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
