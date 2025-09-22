# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105617");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-04-21 14:11:13 +0200 (Thu, 21 Apr 2016)");
  script_name("Cisco Prime Network Control System Version Detection");

  script_tag(name:"summary", value:"This Script performs SSH based detection of Cisco Prime Network Control System");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_ncs/show_ver");
  exit(0);
}

include("host_details.inc");

if( ! system = get_kb_item( "cisco_ncs/show_ver" ) ) exit( 0 );
if( "Cisco Prime Network Control System" >!< system ) exit( 0 );

cpe = 'cpe:/a:cisco:prime_network_control_system';
vers = 'unknown';
set_kb_item( name:"cisco/ncs/installed", value:TRUE );

lines = split( system );
foreach line ( lines )
{
  if( "Cisco Prime Network Control System" >< line ) break;
  system -= line;
}

version = eregmatch( pattern:'Version\\s*:\\s*([0-9]+[^\r\n]+)', string:system );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
  set_kb_item( name:"cisco/ncs/version", value:vers );
}

register_product( cpe:cpe, location:'ssh' );

report = build_detection_report( app:'Cisco Prime Network Control System', version:vers, install:'ssh', cpe:cpe, concluded:'show version' );
log_message( port:0, data:report );
exit( 0 );

