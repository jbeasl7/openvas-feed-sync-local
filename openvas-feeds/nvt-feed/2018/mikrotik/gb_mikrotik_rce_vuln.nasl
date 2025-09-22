# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140895");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-03-28 12:42:03 +0700 (Wed, 28 Mar 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-27 18:28:38 +0000 (Mon, 27 Jan 2025)");

  script_cve_id("CVE-2018-7445");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS < 6.41.3 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a remote code execution (RCE)
  vulnerability in the SMB service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The buffer overflow was found in the MikroTik RouterOS SMB
  service when processing NetBIOS session request messages. Remote attackers with access to the
  service can exploit this vulnerability and gain code execution on the system. The overflow occurs
  before authentication takes place, so it is possible for an unauthenticated remote attacker to
  exploit it.");

  script_tag(name:"affected", value:"MikroTik RouterOS prior to version 6.41.3.");

  script_tag(name:"solution", value:"Update to version 6.41.3 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44290/");
  script_xref(name:"URL", value:"https://www.coresecurity.com/advisories/mikrotik-routeros-smb-buffer-overflow");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.41.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.41.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
