# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145885");
  script_version("2026-09-16T05:46:31+0000");
  script_tag(name:"last_modification", value:"2026-09-16 05:46:31 +0000 (Wed, 16 Sep 2026)");
  script_tag(name:"creation_date", value:"2021-05-04 05:09:01 +0000 (Tue, 04 May 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-10 12:43:55 +0000 (Mon, 10 May 2021)");

  # nb: CVE-2020-20218 and CVE-2020-20247 appear to describe the same underlying
  # /nova/bin/traceroute memory corruption vulnerability for different RouterOS release trees. Both
  # CVE records are currently active.
  script_cve_id("CVE-2020-20218", "CVE-2020-20247");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.46.5 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS suffers from a memory corruption vulnerability
  in the /nova/bin/traceroute process.");

  script_tag(name:"impact", value:"An authenticated remote attacker can cause a DoS via the loop
  counter variable.");

  # nb: CVE/researcher confirms the 6.44.6 long-term version affected but the flaw unlikely affected
  # only a single version...
  script_tag(name:"affected", value:"MikroTik RouterOS version 6.44.6 and probably prior, 6.45.x
  prior to 6.46.5.");

  script_tag(name:"solution", value:"Update to version 6.46.5 or later.");

  # nb: Initial disclosure of the traceroute flaw covered here and a separate cerm flaw. The
  # researcher later assigned CVE-2020-20218 to the traceroute flaw. CVE-2020-20247 independently
  # references this disclosure and appears to duplicate CVE-2020-20218 for the stable release tree:
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2020/May/30");

  # nb: Researcher's later CVE assignment of CVE-2020-20218 to the traceroute
  # flaw and CVE-2020-20221 to the separate cerm flaw:
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2021/May/1");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs?channelFilter=&versionFilter=6.46.5");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/t/v6-46-5-stable-is-released/138353/1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: Version 6.44.6 was the last published final release in the 6.44.x
# branch. The next final RouterOS release was 6.45.
if (version_is_less_equal(version: version, test_version: "6.44.6") ||
    version_in_range_exclusive(version: version, test_version_lo: "6.45.0", test_version_up: "6.46.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.46.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
