# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:iox";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106466");
  script_cve_id("CVE-2016-9199");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco IOx Application-Hosting Framework Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-caf");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 1.2.0.0");

  script_tag(name:"summary", value:"A vulnerability in the Cisco application-hosting framework (CAF) of Cisco
IOx could allow an authenticated, remote attacker to read arbitrary files on a targeted system.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation by the affected
framework. An attacker could exploit this vulnerability by submitting specific, crafted input to the affected
framework on a targeted system.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to read arbitrary files on the
targeted system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 18:22:00 +0000 (Thu, 22 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-12-12 14:57:52 +0700 (Mon, 12 Dec 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_iox_web_detect.nasl");
  script_mandatory_keys("cisco_iox/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "www"))
  exit(0);

if (version == '1.1.0.0') {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.0.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit( 99 );

