# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112878");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-04-07 09:30:11 +0000 (Wed, 07 Apr 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 18:16:00 +0000 (Fri, 04 Jun 2021)");

  script_cve_id("CVE-2021-28658");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 2.2 < 2.2.20, 3.0 < 3.0.14, 3.1 < 3.1.8 Directory Traversal Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to a directory traversal vulnerability.");

  script_tag(name:"insight", value:"MultiPartParser allowed directory-traversal via uploaded files with suitably crafted file names.

  Built-in upload handlers were not affected by this vulnerability");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access arbitrary
  files and directories on the file system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django 2.2 before 2.2.20, 3.0 before 3.0.14, and 3.1 before 3.1.8");

  script_tag(name:"solution", value:"Update to version 2.2.20, 3.0.14, 3.1.8 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2021/apr/06/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.20", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.14", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if(version_in_range(version: version, test_version: "3.1.0", test_version2: "3.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.8", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
