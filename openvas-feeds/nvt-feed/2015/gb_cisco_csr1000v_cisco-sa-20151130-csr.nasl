# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105474");
  script_cve_id("CVE-2015-6385");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Cloud Services Router 1000V Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151130-csr");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper input validation of event manager environment variables that are configured on the affected device. An attacker could exploit this vulnerability by authenticating to the device with administrative privileges, modifying the configuration of the device, and then invoking a crafted event manager script. A successful exploit could allow the attacker to compromise the affected system using commands that are executed with root-level privileges.");
  script_tag(name:"solution", value:"See vendor advisory for a solution");
  script_tag(name:"summary", value:"A vulnerability in the event manager environment and publish-event function of the Cisco Cloud Services Router 1000V Series could allow an authenticated, local attacker to perform a command injection attack with root-level privileges.");
  script_tag(name:"affected", value:"Cisco Cloud Services Router 1000V Series running Cisco IOS software versions 15.5(2)S and 15.5(3)S.");
  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-01 17:22:52 +0100 (Tue, 01 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version", "cisco_ios/model");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );
if( ! model = get_kb_item( "cisco_ios/model" ) ) exit( 0 );

if( model !~ '^CSR1[0-9]+V' ) exit( 0 );

affected = make_list( "15.5(2)S","15.5(3)S" );

foreach a ( affected )
{
  if( a == version )
  {
    report = 'Installed version: ' + version + '\n' +
             'Model:             ' + model + '\n' +
             'Fixed version:     See vendor advisory';
    security_message( port:0, data:report);
    exit( 0 );
  }
}

exit( 99 );
