# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106734");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-10 10:27:18 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-6598");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco UCS Manager Debug Plug-in Privilege Escalation Vulnerability (cisco-sa-20170405-ucs)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_manager_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_manager/detected");

  script_tag(name:"summary", value:"A vulnerability in the debug plug-in functionality of the Cisco
  Unified Computing System (UCS) Manager could allow an authenticated, local attacker to execute
  arbitrary commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to inadequate integrity checks for the
  debug plug-in. An attacker could exploit this vulnerability by crafting a debug plug-in and
  loading it using elevated privileges.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to run malicious code that
  would allow for the execution of arbitrary commands as root.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ucs");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version == "3.1(1k)A") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
