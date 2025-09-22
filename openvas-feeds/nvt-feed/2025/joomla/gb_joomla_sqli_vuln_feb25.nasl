# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154036");
  script_version("2025-03-14T05:38:04+0000");
  script_tag(name:"last_modification", value:"2025-03-14 05:38:04 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-02-19 02:16:42 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:N/A:N");

  script_cve_id("CVE-2025-22207");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! SQLi Vulnerability (20250201)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to an SQL injection (SQLi) vulnerability in
  the Scheduled Tasks component.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improperly built order clauses lead to an SQL injection
  vulnerability in the backend task list of com_scheduler.");

  script_tag(name:"affected", value:"Joomla! version 4.1.0 through 4.4.10 and 5.0.0 through
  5.2.3.");

  script_tag(name:"solution", value:"Update to version 4.4.11, 5.2.4 or later.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/958-20250201-core-sql-injection-vulnerability-in-scheduled-tasks-component.html");

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

if (version_in_range(version: version, test_version: "4.1.0", test_version2: "4.4.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
