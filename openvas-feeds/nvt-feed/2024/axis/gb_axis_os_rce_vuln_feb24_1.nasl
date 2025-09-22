# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:axis:axis_os";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.127710");
  script_version("2024-03-06T05:05:53+0000");
  script_tag(name:"last_modification", value:"2024-03-06 05:05:53 +0000 (Wed, 06 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-02-28 08:36:17 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 00:38:00 +0000 (Tue, 13 Feb 2024)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-5677");

  script_name("AXIS OS RCE Vulnerability (Feb 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected", "axis/device/model");

  script_tag(name:"summary", value:"AXIS OS is prone to a remote code execution (RCE)
  vulnerability on severaldevices.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An insufficient input validation in the VAPIX API tcptest.cgi
  leads to a remote code execution.");

  script_tag(name:"affected", value:"Axis M3024-L, M3025-VE, M7014, M7016, P1214(-E), P7214, P7216,
  Q7401, Q7404, Q7414 running AXIS OS 5.50 prior to 5.51.7.7 and AXIS Q7424-R Mk II
  running AXIS OS 5.50 prior to 5.51.3.9.");

  script_tag(name:"solution", value:"Update to version 5.51.7.7, 5.51.3.9 or later.");

  script_xref(name:"URL", value:"https://www.axis.com/dam/public/a9/dd/f1/cve-2023-5677-en-US-424335.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (!model = get_kb_item("axis/device/model"))
  exit(0);

if (model =~ "^M3024-L" ||
    model =~ "^M3025-VE" ||
    model =~ "^M7014" ||
    model =~ "^M7016" ||
    model =~ "^P1214\(-E\)" ||
    model =~ "^P7214" ||
    model =~ "^P7216" ||
    model =~ "^Q7401" ||
    model =~ "^Q7404" ||
    model =~ "^Q7414") {

  if (version_in_range_exclusive(version: version, test_version_lo: "5.50.0.0", test_version_up: "5.51.7.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "5.51.7.7");
    security_message(data: report, port: 0);
    exit(0);
  }

} else if (model =~ "^Q7424-R Mk II") {
    if (version_in_range_exclusive(version: version, test_version_lo: "5.50.0.0", test_version_up: "5.51.3.9")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "5.51.3.9");
      security_message(data: report, port: 0);
      exit(0);
    }
  }

exit(99);
