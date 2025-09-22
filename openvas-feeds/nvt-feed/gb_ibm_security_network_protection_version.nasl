# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105746");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-01 15:10:02 +0200 (Wed, 01 Jun 2016)");
  script_name("IBM Security Network Protection Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of IBM Security Network Protection");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("isnp/detected");
  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

firmware = ssh_cmd( socket:sock, cmd:'firmware list', nosh:TRUE, pty:TRUE, timeout:30, retry:10 );

if( "Firmware Version:" >!< firmware ) exit( 0 );
vers = "unknown";
cpe = 'cpe:/a:ibm:security_network_protection';

fw = split( firmware, keep:FALSE );

for( i=0; i < max_index( fw ); i++ )
{
  if( "ACTIVE" >< fw[i] )
  {
    version = eregmatch( pattern:'IBM Security Network Protection ([0-9]+[^\r\n]+)', string:fw[i + 1]);
    if( ! isnull( version[1] ) )
    {
      vers = version[1];
      cpe += ':' + vers;
    }
    break;
  }
}

set_kb_item( name:"isnp/version", value:vers );

register_product( cpe:cpe, location:"ssh" );

report = build_detection_report( app:"IBM Security Network Protection", version:vers, install:"ssh", cpe:cpe, concluded:"firmware list" );
log_message( port:0, data:report );

exit( 0 );

