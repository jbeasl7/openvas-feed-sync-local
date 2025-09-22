# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154359");
  script_version("2025-06-19T05:40:14+0000");
  script_tag(name:"last_modification", value:"2025-06-19 05:40:14 +0000 (Thu, 19 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-04-23 03:06:17 +0000 (Wed, 23 Apr 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2025-24914");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus Privilege Escalation Vulnerability (TNS-2025-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_tenable_nessus_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("tenable/nessus/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When installing Nessus to a non-default location on a Windows
  host, Nessus does not enforce secure permissions for sub-directories. This could allow for local
  privilege escalation if users had not secured the directories in the non-default installation
  location.");

  script_tag(name:"affected", value:"Tenable Nessus prior to version 10.8.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 10.8.4 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2025-05");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.8.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
