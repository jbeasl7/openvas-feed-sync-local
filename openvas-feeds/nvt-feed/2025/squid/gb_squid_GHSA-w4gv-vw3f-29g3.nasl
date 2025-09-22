# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155085");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-04 02:20:49 +0000 (Mon, 04 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 16:55:12 +0000 (Tue, 26 Aug 2025)");

  script_cve_id("CVE-2025-54574");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Buffer Overflow Vulnerability (GHSA-w4gv-vw3f-29g3, SQUID-2025:1)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a buffer overflow vulnerability in URN
  handling.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to incorrect buffer management Squid is vulnerable to a
  heap buffer overflow and possible remote code execution attack when processing URN.");

  script_tag(name:"affected", value:"Squid prior to version 6.4.");

  script_tag(name:"solution", value:"Update to version 6.4 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-w4gv-vw3f-29g3");

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

if (version_is_less(version: version, test_version: "6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
