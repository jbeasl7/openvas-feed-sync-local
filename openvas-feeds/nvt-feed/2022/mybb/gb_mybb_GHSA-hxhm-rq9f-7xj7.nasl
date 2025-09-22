# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127217");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-10-10 10:12:46 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 18:47:00 +0000 (Fri, 07 Oct 2022)");

  script_cve_id("CVE-2022-39265");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.31 RCE Vulnerability (GHSA-hxhm-rq9f-7xj7)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_mandatory_keys("mybb/detected");

  script_tag(name:"summary", value:"MyBB is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The 'Mail Settings' -> 'Additional Parameters for PHP's
  mail()' (mail_parameters) setting value, in connection with the configured mail program's
  optionsand behavior, may allow access to sensitive information and Remote Code Execution (RCE).

  The vulnerable module requires Admin CP access with the 'Can manage settings?' permission and may
  depend on configured file permissions.");

  script_tag(name:"affected", value:"MyBB prior to version 1.8.31.");

  script_tag(name:"solution", value:"Update to version 1.8.31 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-hxhm-rq9f-7xj7");

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

if (version_is_less(version: version, test_version: "1.8.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
