# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106254");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-09-16 12:38:55 +0700 (Fri, 16 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");

  script_cve_id("CVE-2016-6402");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Computing System Command Line Interface Privilege Escalation Vulnerability (cisco-sa-20160914-ucs)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_manager_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_manager/detected");

  script_tag(name:"summary", value:"A vulnerability in the command-line interface (CLI) of the
  Cisco Unified Computing System (UCS) Manager and UCS 6200 Series Fabric Interconnects could allow
  an authenticated, local attacker to access the underlying operating system with the privileges of
  the root user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of
  user-supplied input at the CLI.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by bypassing policy
  restrictions and executing commands on the underlying operating system. The user needs to log in
  to the device with valid user credentials to exploit this vulnerability.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-ucs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

affected = make_list(
  "2.2(1b)",
  "2.2(1c)",
  "2.2(1d)",
  "2.2(1e)",
  "2.2(1f)",
  "2.2(1g)",
  "2.2(1h)",
  "2.2(2c)",
  "2.2(2c)A",
  "2.2(2d)",
  "2.2(2e)",
  "2.2(3a)",
  "2.2(3b)",
  "2.2(3c)",
  "2.2(3d)",
  "2.2(3e)",
  "2.2(3f)",
  "2.2(3g)",
  "2.2(4b)",
  "2.2(4c)",
  "2.2(5a)",
  "2.2(5b)A",
  "3.0(1c)",
  "3.0(1d)",
  "3.0(1e)",
  "3.0(2c)",
  "3.0(2d)");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
