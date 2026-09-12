# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813155");
  script_version("2026-09-11T15:35:37+0000");
  script_tag(name:"last_modification", value:"2026-09-11 15:35:37 +0000 (Fri, 11 Sep 2026)");
  script_tag(name:"creation_date", value:"2018-04-25 11:34:56 +0530 (Wed, 25 Apr 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-23 17:23:23 +0000 (Thu, 23 Jan 2025)");

  script_cve_id("CVE-2018-14847");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS 'Winbox Service' Information Disclosure Vulnerability (Apr 2018) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the winbox service of
  routeros which allows remote users to download a user database file without successful
  authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to connect
  to the WinBox port and download a user database file. The remote user can then log in and take
  control of the router.");

  script_tag(name:"affected", value:"MikroTik RouterOS versions 6.29 through 6.42 and 6.43rcx prior
  to 6.43rc4.");

  script_tag(name:"solution", value:"Update to version 6.40.8, 6.42.1, 6.43rc4 or later.");

  # nb: This was initially at https://blog.mikrotik.com/security/winbox-vulnerability.html
  script_xref(name:"URL", value:"https://mikrotik.com/supportsec/winbox-vulnerability/");
  script_xref(name:"URL", value:"https://mikrotik.com/supportsec/new-exploit-for-mikrotik-router-winbox-vulnerability/");
  # nb: This was initially at https://forum.mikrotik.com/viewtopic.php?t=133533
  script_xref(name:"URL", value:"https://forum.mikrotik.com/t/advisory-vulnerability-exploiting-the-winbox-port-solved/118771");
  # nb: This was initially at https://n0p.me/winbox-bug-dissection/
  script_xref(name:"URL", value:"https://blog.n0p.me/2018/05/2018-05-21-winbox-bug-dissection/");
  script_xref(name:"URL", value:"https://github.com/BasuCert/WinboxPoC");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  # nb: This Botnet seems to have misused this flaw:
  script_xref(name:"URL", value:"https://mikrotik.com/supportsec/meris-botnet/");
  script_xref(name:"URL", value:"https://blog.qrator.net/en/meris-botnet-climbing-to-the-record_142/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

# nb: This is a simplified variant of what the vendor has published on the advisory:
#
# > Affected all bugfix releases from 6.30.1 to 6.40.7, fixed in 6.40.8
# > Affected all current releases from 6.29 to 6.42, fixed in 6.42.1
# > Affected all RC releases from 6.29rc1 to 6.43rc3, fixed in 6.43rc4
#
# and which should be enough for our purposes.
if (version_in_range(version:version, test_version:"6.29", test_version2:"6.40.7")) {
  fix = "6.40.8";
} else if (version_in_range(version:version, test_version:"6.41", test_version2:"6.42")) {
  fix = "6.42.1";
} else if (version == "6.29rc1" || version == "6.43rc1" || version == "6.43rc2" || version == "6.43rc3") {
  fix = "6.43rc4";
}

if (fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
