# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127740");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-05-02 10:45:46 +0000 (Thu, 02 May 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");

  script_cve_id("CVE-2024-23335", "CVE-2024-23336");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MyBB < 1.8.38 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_mandatory_keys("mybb/detected");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-23335: The backup management module of the Admin CP may accept .htaccess as the name of
  the backup file to be deleted, which may expose the stored backup files over HTTP on Apache
  servers.

  - CVE-2024-23336: The default list of disallowed remote hosts does not contain the '127.0.0.0/8'
  block, which may result in a SSRF vulnerability.");

  script_tag(name:"affected", value:"MyBB prior to version 1.8.38.");

  script_tag(name:"solution", value:"Update to version 1.8.38 or later.");

  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-94xr-g4ww-j47r");
  script_xref(name:"URL", value:"https://github.com/mybb/mybb/security/advisories/GHSA-qfrj-65mv-h75h");

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

if (version_is_less(version: version, test_version: "1.8.38")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.8.38", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
