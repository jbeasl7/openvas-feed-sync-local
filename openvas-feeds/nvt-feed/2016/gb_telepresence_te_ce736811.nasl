# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107002");
  script_cve_id("CVE-2016-1387");

  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_version("2025-09-09T14:09:45+0000");

  script_name("Cisco TelePresence XML Application Programming Interface Authentication Bypass Vulnerability (cisco-sa-20160504-tpxml)");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160504-tpxml");

  script_tag(name:"last_modification", value:"2025-09-09 14:09:45 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-01 03:05:00 +0000 (Thu, 01 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-13 16:46:52 +0200 (Fri, 13 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_telepresence_snmp_detect.nasl", "gb_cisco_telepresence_ftp_detect.nasl");
  script_mandatory_keys("cisco/telepresence/typ", "cisco/telepresence/version");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to perform unauthorized configuration changes
  or issue control commands to the affected system by using the API.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper implementation of authentication mechanisms for the XML
  API of the affected software. An attacker could exploit this vulnerability by sending a crafted HTTP request to the XML API.");

  script_tag(name:"solution", value:"Update to version 7.3.6, 8.1.1 or later.");

  script_tag(name:"summary", value:"Cisco TelePresence Codec (TC) and Collaboration Endpoint (CE) Software are vulnerable to a
  vulnerability in the XML application programming interface (API) which could allow an unauthenticated, remote
  attacker to bypass authentication and access a targeted system through the API");

  script_tag(name:"affected", value:"This vulnerability affects Cisco TelePresence Software releases TC 7.2.0, TC 7.2.1, TC 7.3.0,
  TC 7.3.1, TC 7.3.2, TC 7.3.3, TC 7.3.4, TC 7.3.5, CE 8.0.0, CE 8.0.1, and CE 8.1.0 running on the following Cisco products:

  - TelePresence EX Series

  - TelePresence Integrator C Series

  - TelePresence MX Series

  - TelePresence Profile Series

  - TelePresence SX Series

  - TelePresence SX Quick Set Series

  - TelePresence VX Clinical Assistant

  - TelePresence VX Tactical");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version(cpe:CPE) ) exit( 0 );
if( ! typ = get_kb_item( "cisco/telepresence/typ" ) ) exit( 0 );

if( typ !~ ' EX(6|9)0$' && typ !~ ' C(2|4|6|9)0$' &&
    typ !~ ' SX(1|2|8)0$' && typ !~ 'MX(2|3|7|8)00$' && typ !~ 'G2$'
    && typ !~ 'SpeakerTrack$' && typ !~ ' (42|52)/55$' && typ !~ ' (42|52)/55( Dual$)'
    && typ !~ ' (42|52)/55( C40$)')  exit( 0 );

version = eregmatch(pattern: "^T[CE]([^$]+$)", string:vers, icase:TRUE);

if( isnull( version[1] ) ) exit( 0 );

verscat = version[0];
vers = version[1];

if (verscat =~ "^ce.")
{
  if( vers =~ "^8\.0\.[0|1]" || vers =~ "^8\.1\.0\.") fix = '8.1.1';
}
else if (verscat =~ "^tc.")
{
  if( vers =~ "^7\.2\.[0|1]" || vers =~ "^7\.3\.[0-5]")  fix = '7.3.6';
}

if( ! fix ) exit( 0 );

if( version_is_less( version:vers, test_version:fix ) )
{
  report = 'Installed version: ' + vers + '\nFixed version:     ' + fix;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
