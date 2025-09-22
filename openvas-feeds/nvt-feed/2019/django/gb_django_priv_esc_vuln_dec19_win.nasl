# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143234");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-12-09 04:50:09 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-01 02:15:00 +0000 (Fri, 01 May 2020)");

  script_cve_id("CVE-2019-19118");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 2.1.x < 2.1.15, 2.2.x < 2.2.8 Privilege Escalation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to a privilege escalation vulnerability.");

  script_tag(name:"insight", value:"A Django model admin displaying inline related models, where the user has
  view-only permissions to a parent model but edit permissions to the inline model, would be presented with an
  editing UI, allowing POST requests, for updating the inline model. Directly editing the view-only parent model
  was not possible, but the parent model's save() method was called, triggering potential side effects, and
  causing pre and post-save signal handlers to be invoked.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django versions 2.1.x and 2.2.x.");

  script_tag(name:"solution", value:"Update to version 2.1.15, 2.2.8 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/dec/02/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.1.0", test_version2: "2.1.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.15", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.8", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
