# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105334");
  script_version("2024-02-21T14:36:44+0000");
  script_tag(name:"last_modification", value:"2024-02-21 14:36:44 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-08-27 15:44:02 +0200 (Thu, 27 Aug 2015)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2015-4314");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco TelePresence Video Communication Server Expressway Information Disclosure Vulnerability (Cisco-SA-20150812-CVE-2015-4314)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_vcs_consolidation.nasl");
  script_mandatory_keys("cisco/vcs/detected");

  script_tag(name:"summary", value:"A vulnerability in the System Snapshot of Cisco TelePresence
  Video Communication Server (VCS) Expressway could allow an authenticated, remote attacker to view
  sensitive data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient protection of data at
  rest. An attacker could exploit this vulnerability by downloading the snapshot file and viewing
  the password hashes in it.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to crack the password hashes
  and use the credentials to launch further attacks.");

  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server Expressway
  version X8.5.1.");

  script_tag(name:"solution", value:"Update to version X8.7 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76326");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150812-CVE-2015-4314");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version =~ "^8\.5\.1($|[^0-9])" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.7" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
