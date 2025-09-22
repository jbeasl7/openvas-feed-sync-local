# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:qnap:video_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153037");
  script_version("2024-09-30T08:38:05+0000");
  script_tag(name:"last_modification", value:"2024-09-30 08:38:05 +0000 (Mon, 30 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-10 02:23:27 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-28 23:44:50 +0000 (Sat, 28 Sep 2024)");

  script_cve_id("CVE-2023-47563", "CVE-2023-50360");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Video Station Multiple Vulnerabilities (QSA-24-24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_videostation_http_detect.nasl");
  script_mandatory_keys("qnap/videostation/detected");

  script_tag(name:"summary", value:"QNAP Video Station is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-47563: OS command injection could allow remote attackers to execute arbitrary commands
  on the operating system through the application's input

  - CVE-2023-50360: SQL injection (SQLi) could allow attackers to inject malicious code");

  script_tag(name:"affected", value:"QNAP Video Station version 5.x.");

  script_tag(name:"solution", value:"Update to version 5.8.2 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-24");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.8.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.8.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
