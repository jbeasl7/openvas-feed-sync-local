# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106168");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-08-04 13:00:53 +0700 (Thu, 04 Aug 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-1468");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco TelePresence Video Communication Server Expressway Command Injection Vulnerability (cisco-sa-20160803-vcse)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"A vulnerability in the administrative web interface of Cisco
  TelePresence Video Communication Server Expressway could allow an authenticated, remote attacker
  to execute arbitrary commands on the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to the failure to properly sanitize
  user input passed to the affected system's scripts. An attacker could exploit this vulnerability
  by submitting crafted input to the affected fields of the web interface.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability could allow an
  attacker to run arbitrary commands on the system.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server Expressway
  version X8.5.2.");

  script_tag(name:"solution", value:"Update to version X8.6 or later");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160803-vcse");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_equal(version: version, test_version: "8.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
