# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141395");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-08-24 14:27:31 +0700 (Fri, 24 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2018-1156", "CVE-2018-1157", "CVE-2018-1158", "CVE-2018-1159");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS Multiple Vulnerabilities (Aug 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to multiple vulnerabilitites.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MikroTik RouterOS is prone to multiple vulnerabilitites:

  - CVE-2018-1156: Stack buffer overflow through the license upgrade interface

  - CVE-2018-1157: Memory exhaustion

  - CVE-2018-1158: Stack exhaustion

  - CVE-2018-1159: Memory corruption");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.42.7 and 6.40.9.");

  script_tag(name:"solution", value:"Update to version 6.43, 6.42.7, 6.40.9 or later.");

  script_xref(name:"URL", value:"https://blog.mikrotik.com/security/security-issues-discovered-by-tenable.html");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/bugfix-release-tree");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/release-candidate-release-tree");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.40.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.40.9");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.41", test_version2: "6.42.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.42.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
