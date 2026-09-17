# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145883");
  script_version("2026-09-16T05:46:31+0000");
  script_tag(name:"last_modification", value:"2026-09-16 05:46:31 +0000 (Wed, 16 Sep 2026)");
  script_tag(name:"creation_date", value:"2021-05-04 04:56:40 +0000 (Tue, 04 May 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-30 13:17:08 +0000 (Fri, 30 Jul 2021)");

  script_cve_id("CVE-2020-20221");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.44.6, 6.45.x <= 6.45.7 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS suffers from an uncontrolled resource
  consumption vulnerability in the /nova/bin/cerm process.");

  script_tag(name:"impact", value:"An authenticated remote attacker can cause a DoS due to
  overloading the systems CPU.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions prior to 6.44.6 and 6.45.x version
  6.45.7 and probably prior.");

  script_tag(name:"solution", value:"Update to version 6.44.6, 6.46 or later.");

  # nb: Initial disclosure of the cerm flaw covered here and a separate traceroute flaw. The
  # researcher later (see next reference) assigned CVE-2020-20221 to the cerm flaw.
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2020/May/30");

  # nb: Researcher's later CVE assignment of CVE-2020-20221 to the cerm flaw and CVE-2020-20218 to
  # the separate traceroute flaw:
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2021/May/1");

  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs?channelFilter=&versionFilter=6.44.6");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/t/v6-44-6-long-term-is-released/134263/1");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs?channelFilter=&versionFilter=6.46");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/t/v6-46-stable-is-released/135149");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.44.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.44.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.45.0", test_version2: "6.45.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.46");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
