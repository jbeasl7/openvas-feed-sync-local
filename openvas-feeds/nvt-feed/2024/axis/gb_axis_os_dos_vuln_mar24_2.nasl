# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:axis:axis_os";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.127719");
  script_version("2024-04-05T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-28 12:26:59 +0000 (Thu, 28 Mar 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2024-0055");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("AXIS OS < 10.12.228, 11.x < 11.9.53 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS OS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"VAPIX APIs mediaclip.cgi and playclip.cgi are vulnerable for
  file globbing which could lead to a resource exhaustion attack.");

  script_tag(name:"affected", value:"AXIS OS version 10.12.x prior to 10.12.228 and 11.x prior to
  11.9.53.");

  script_tag(name:"solution", value:"Update to version 10.12.228, 11.9.53 or later.");

  script_xref(name:"URL", value:"https://www.axis.com/dam/public/c4/00/c5/cve-2024-0055-en-US-432117.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "10.12.0", test_version_up: "10.12.228")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.12.228");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0.0", test_version_up: "11.9.53")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.9.53");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
