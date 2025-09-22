# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112679");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-12-19 15:45:00 +0000 (Thu, 19 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-08 04:15:00 +0000 (Wed, 08 Jan 2020)");

  script_cve_id("CVE-2019-19844");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django Account Hijacking Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to an account hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Django's password-reset form uses a case-insensitive query to retrieve
  accounts matching the email address requesting the password reset. Because this typically involves explicit
  or implicit case transformations, an attacker who knows the email address associated with a user account
  can craft an email address which is distinct from the address associated with that account,
  but which -- due to the behavior of Unicode case transformations -- ceases to be distinct after case transformation,
  or which will otherwise compare equal given database case-transformation or collation behavior.");

  script_tag(name:"impact", value:"By successfully exploiting this issue an attacker can receive a valid password-reset token for the user account.");

  script_tag(name:"affected", value:"All Django versions before 1.11.2, 2.x before 2.2.9 and 3.x before 3.0.1.");

  script_tag(name:"solution", value:"Update to version 1.11.2, 2.2.9 or 3.0.1 respectively.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/dec/18/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version: version, test_version: "1.11.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.11.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "2.0", test_version2: "2.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.9", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if(version_is_equal(version: version, test_version: "3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
