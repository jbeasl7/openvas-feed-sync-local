# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103297");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-07-31 07:21:42 +0000 (Wed, 31 Jul 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2024-2169");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.49.12, 7.x < 7.13.3 DoS Vulnerability (Loop DoS)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability dubbed 'Loop DoS'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the MikroTik RouterOS UPD protocol
  implementation. This issue may allow an unauthenticated attacker to send maliciously crafted
  packages leading to a denial of service on the targeted system.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions prior to 6.49.12 and 7.x through
  7.13.2.");

  script_tag(name:"solution", value:"Update to version 6.49.12, 7.13.3 or later.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?t=206092");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/417980#MikroTik");
  script_xref(name:"URL", value:"https://cispa.de/en/loop-dos");
  script_xref(name:"URL", value:"https://cispa.saarland/group/rossow/Loop-DoS");
  script_xref(name:"URL", value:"https://github.com/cispa/loop-DoS");

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

if (version_is_less(version: version, test_version: "6.49.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.13.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.13.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
