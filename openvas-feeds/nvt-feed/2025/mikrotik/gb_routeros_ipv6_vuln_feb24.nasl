# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155026");
  script_version("2025-07-25T15:43:57+0000");
  script_tag(name:"last_modification", value:"2025-07-25 15:43:57 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-25 07:12:57 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2023-47310");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.49.13, 7.x < 7.14 IPv6 Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a vulnerability in the IPv6
  firewall rule.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A misconfiguration in the default settings allows incoming IPv6
  UDP traceroute packets.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.49.13 and 7.x prior to
  7.14.");

  script_tag(name:"solution", value:"Update to version 6.49.13, 7.14 or later.");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/t/fixed-in-7-14-security-vulnerability-default-configuration-firewall-bypass-for-ipv6-udp/262186/2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.49.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.49.13");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.14");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
