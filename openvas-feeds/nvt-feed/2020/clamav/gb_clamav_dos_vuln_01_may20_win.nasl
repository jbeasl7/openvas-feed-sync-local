# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112748");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-05-18 11:44:00 +0000 (Mon, 18 May 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 08:15:00 +0000 (Thu, 06 Aug 2020)");

  script_cve_id("CVE-2020-3327");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV 0.102.2 < 0.102.4 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Improper bounds checking of an unsigned variable results in an
  out-of-bounds read which causes a crash.");

  script_tag(name:"impact", value:"Successful exploitation would cause a denial-of-service
  condition.");

  script_tag(name:"affected", value:"ClamAV version 0.102.2 and 0.102.3.");

  script_tag(name:"solution", value:"Update to version 0.102.4 or later.");

  script_xref(name:"URL", value:"https://blog.clamav.net/2020/05/clamav-01023-security-patch-released.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2020/07/clamav-01024-security-patch-released.html");

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

if (version_in_range(version: version, test_version: "0.102.2", test_version2: "0.102.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.102.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
