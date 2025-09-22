# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144572");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-09-15 02:09:54 +0000 (Tue, 15 Sep 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 16:30:00 +0000 (Fri, 18 Sep 2020)");

  script_cve_id("CVE-2020-11881");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.46.7, 6.47.x < 6.48beta40, 7.x < 7.1beta3 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a denial of service (DoS)
  vulnerability in the SMB server.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An array index error in MikroTik RouterOS allows an
  unauthenticated remote attacker to crash the SMB server via modified setup-request packets, aka
  SUP-12964.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions prior to 6.46.7, 6.47.x prior to
  6.48beta40 and 7.x prior to 7.1beta3.");

  script_tag(name:"solution", value:"- Update to version 6.46.7 (long-term release), 6.48beta40
  (testing release), 7.1beta3 (development release) or later

  - Disable the SMB server / functionality

  Note: Please set an override for this result if the SMB server / functionality is already
  disabled");

  script_xref(name:"URL", value:"https://github.com/botlabsDev/CVE-2020-11881");
  script_xref(name:"URL", value:"https://forum.mikrotik.com/viewtopic.php?f=2&t=166137");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/long-term-release-tree#show-tab-tree_3-id-8d07e91d70a09af6d7c73ecfbe2aa96a");
  script_xref(name:"URL", value:"https://mikrotik.com/download/changelogs/testing-release-tree#show-tab-tree_2-id-00066a89cafeebda2054b2ca153ef829");
  # nb: The following posting includes a confirmation (currently missing on the official changelogs)
  # from vendor side about the fixed status of the 7.x branch
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/mikrotik-routeros-6-46-7-6-47-3-7-x-dos-vulnerability/14982/11");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.46.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.46.7");
  security_message(port: 0, data: report);
  exit(0);
}

# nb on the next two checks: Our detection currently probably doesn't detect / extract e.g. 7.1beta3
# or 6.48beta40 so we're just using 7.0 and 6.47 as being affected here for simplicity as most
# users are probably not using such development / testing versions at all.
if (version =~ "^6\.47") {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.48beta40");
  security_message(port: 0, data: report);
  exit(0);
}

if (version =~ "^7\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1beta3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
