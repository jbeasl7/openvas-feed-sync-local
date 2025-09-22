# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171570");
  script_version("2025-08-13T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-08-13 05:40:47 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-07-02 19:43:35 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-11 18:24:39 +0000 (Mon, 11 Aug 2025)");

  script_cve_id("CVE-2025-20234");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV 1.2 < 1.4.3 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in Universal Disk Format (UDF) processing of
  ClamAV exists due to a memory overread during UDF file scanning. An attacker could exploit this
  vulnerability by submitting a crafted file containing UDF content to be scanned by ClamAV on an
  affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to terminate the
  ClamAV scanning process, resulting in a DoS condition on the affected software.");

  script_tag(name:"affected", value:"ClamAV version 1.2 prior to 1.4.3.");

  script_tag(name:"solution", value:"Update to version 1.4.3 or later.");

  script_xref(name:"URL", value:"https://blog.clamav.net/2025/06/clamav-143-and-109-security-patch.html");
  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-clamav-udf-hmwd9nDy");

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

if (version_in_range_exclusive(version: version, test_version_lo: "1.2.0", test_version_up: "1.4.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
