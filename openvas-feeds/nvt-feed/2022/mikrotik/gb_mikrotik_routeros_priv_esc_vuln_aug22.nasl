# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:mikrotik:routeros";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124147");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-08-29 10:35:22 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 16:35:00 +0000 (Wed, 31 Aug 2022)");

  script_cve_id("CVE-2022-34960");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MikroTik RouterOS Privilege Escalation Vulnerability (CVE-2022-34960)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_mikrotik_router_routeros_consolidation.nasl");
  script_mandatory_keys("mikrotik/routeros/detected");

  script_tag(name:"summary", value:"MikroTik RouterOS is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The container package in MikroTik RouterOS allows an attacker
  to create mount points pointing to symbolic links, which resolve to locations on the host device.
  This allows the attacker to mount any arbitrary file to any location on the host.");

  script_tag(name:"affected", value:"MikroTik RouterOS version 7.4beta4.");

  script_tag(name:"solution", value:"Update to version 7.4beta5 or later.");

  script_xref(name:"URL", value:"https://nns.ee/blog/2022/08/05/routeros-container-rce.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.4beta4", test_version_up: "7.4beta5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4beta5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
