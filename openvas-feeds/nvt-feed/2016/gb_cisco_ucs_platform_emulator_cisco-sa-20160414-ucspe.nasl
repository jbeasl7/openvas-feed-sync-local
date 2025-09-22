# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system_platform_emulator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105800");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-07-07 11:28:50 +0200 (Thu, 07 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-29 16:32:00 +0000 (Fri, 29 Jul 2016)");

  script_cve_id("CVE-2016-1339", "CVE-2016-1340");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unified Computing System Platform Emulator Command Injection/Buffer Overflow Vulnerability (cisco-sa-20160414-ucspe1, cisco-sa-20160414-ucspe2)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ucs_platform_emulator_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_platform_emulator/detected");

  script_tag(name:"summary", value:"Cisco Unified Computing System Platform Emulator is prone to
  multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  CVE-2016-1339: A vulnerability in the Cisco Unified Computing System (UCS) Platform Emulator
  could allow an authenticated, local attacker to perform a command injection attack.

  CVE-2016-1340: A vulnerability in Cisco Unified Computing System (UCS) Platform Emulator could
  allow an authenticated, local attacker to trigger a heap-based buffer overflow on a targeted
  system.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160414-ucspe1");
  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160414-ucspe2");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if( version =~ '^[0-3](\\.|\\()' || version =~ '3\\.1\\([0-9][a-d]PE' || version =~ '^3\\.1\\(1ePE0\\)' ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1(1ePE1)" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
