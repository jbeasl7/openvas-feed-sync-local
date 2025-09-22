# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:modx:revolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106799");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-05-15 08:46:55 +0700 (Mon, 15 May 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-30 19:05:00 +0000 (Tue, 30 May 2017)");

  script_cve_id("CVE-2017-9067", "CVE-2017-9068", "CVE-2017-9069", "CVE-2017-9070",
                "CVE-2017-9071", "CVE-2017-1000067");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX CMS 2.x < 2.5.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_http_detect.nasl");
  script_mandatory_keys("modx/cms/detected");

  script_tag(name:"summary", value:"MODX CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS in UserGroup names and various other fields

  - User/email enumeration in forgot password feature

  - XSS cache poisoning via Host header

  - Reflected XSS in setup

  - Local file inclusion vulnerability in setup action parameter

  - Various local file inclusion preventions to also protect on windows

  - Stored XSS in resource pagetitle

  - Blind SQL injection

  - PHP code execution");

  script_tag(name:"affected", value:"MODX CMS version 2.x through 2.5.6.");

  script_tag(name:"solution", value:"Update to version 2.5.7 or later.");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/modxcms/revolution/v2.5.7-pl/core/docs/changelog.txt");
  script_xref(name:"URL", value:"https://bitflipper.eu/finding/2017/05/modx-revolution-256-blind-sql-injection.html");
  script_xref(name:"URL", value:"https://bitflipper.eu/finding/2017/05/modx-revolution-256-php-code-execution.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0", test_version_up: "2.5.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
