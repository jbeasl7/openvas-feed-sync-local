# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171569");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-02 19:38:27 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-18 18:15:23 +0000 (Wed, 18 Jun 2025)");

  script_cve_id("CVE-2025-20260");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV 1.x < 1.0.9, 1.1.x < 1.4.3 Buffer Overflow Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ClamAV is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow write bug exists in the PDF file parser.");

  script_tag(name:"impact", value:"The vulnerability could cause a denial of service (DoS)
  condition or enable remote code execution.This issue only affects configurations where both:

  - The max file-size scan limit is set greater than or equal to 1024MB.

  - The max scan-size scan limit is set greater than or equal to 1025MB.

  The code flaw was present prior to version 1.0.0, but a change in version 1.0.0 that enables
  larger allocations based on untrusted data made it possible to trigger this bug.");

  script_tag(name:"affected", value:"ClamAV version 1.x prior to 1.0.9 and 1.1.x prior to 1.4.3.");

  script_tag(name:"solution", value:"Update to version 1.0.9, 1.4.3 or later.");

  script_xref(name:"URL", value:"https://blog.clamav.net/2025/06/clamav-143-and-109-security-patch.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.0.0", test_version_up: "1.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.0.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.1.0", test_version_up: "1.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
