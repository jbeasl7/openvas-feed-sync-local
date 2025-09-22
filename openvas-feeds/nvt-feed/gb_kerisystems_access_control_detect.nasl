# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105418");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-21 16:57:28 +0200 (Wed, 21 Oct 2015)");
  script_name("Keri Systems Access Control Systems Detection");

  script_tag(name:"summary", value:"This script performs telnet banner based idetection of Keri Systems Access Control systems");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/keri_systems/access_control_system/detected");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");
include("telnet_func.inc");

port = telnet_get_port( default:23 );
if( ! banner = telnet_get_banner( port:port ) ) exit( 0 );
if( "KERI-ENET" >!< banner ) exit( 0 );

version = eregmatch( pattern:'Software version V([^ ]+)( \\(([0-9]+)\\))?', string:banner );

if( ! isnull(version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"keri_systems_access_control/version", value:vers );
}

if( ! isnull(version[3] ) )
{
  build = version[3];
  set_kb_item( name:"keri_systems_access_control/build", value:build );
}

_aes = eregmatch( pattern:'AES library version ([^\r\n]+)', string:banner );
if( ! isnull( _aes[1] ) )
{
  aes = _aes[1];
  set_kb_item( name:"keri_systems_access_control/aes_version", value:aes );
}

report = 'The remote host seems to be running a Keri Systems Access Control system' + '\n';

if( vers ) report += 'Version: ' + vers;
if( build) report += ' (' + build + ')\n';
if( aes ) report += 'AES library version: ' + aes;

log_message( port:port, data:report );
exit( 0 );

