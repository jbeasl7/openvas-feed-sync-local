# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144901");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2020-11-09 03:00:36 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-16 18:41:00 +0000 (Mon, 16 Nov 2020)");

  script_cve_id("CVE-2020-5793");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus 8.9.0 - 8.12.0 File Copy Vulnerability (TNS-2020-08) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("tenable/nessus/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a file copy vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in Nessus on Windows could allow an
  authenticated local attacker to copy user-supplied files to a specially constructed path in a
  specifically named user directory.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by creating a
  malicious file and copying the file to a system directory. The attacker needs valid credentials on
  the Windows system to exploit this vulnerability.");

  script_tag(name:"affected", value:"Tenable Nessus version 8.9.0 through 8.12.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 8.12.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2020-08");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "8.9.0", test_version2: "8.12.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.12.1", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
