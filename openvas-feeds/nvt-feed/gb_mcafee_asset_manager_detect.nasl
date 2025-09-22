# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804421");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-17 11:22:05 +0530 (Thu, 17 Apr 2014)");
  script_name("McAfee Asset Manager Version Detection");

  script_tag(name:"summary", value:"Detection of McAfee Asset Manager.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

mamPort = http_get_port( default:443 );
mamRes = http_get_cache( item:"/login", port:mamPort );

if( ">McAfee Asset Manager" >!< mamRes ) exit( 0 );

mamVer = eregmatch( pattern:'">Version ([0-9.]+)', string:mamRes );
if( mamVer[1] ) {
  set_kb_item( name:"www/" + mamPort + "/McAfee/Asset/Manager", value:mamVer[1] );
}

set_kb_item( name:"McAfee/Asset/Manager/installed", value:TRUE );

cpe = build_cpe( value:mamVer[1], exp:"^([0-9.]+)", base:"cpe:/a:mcafee:asset_manager:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:mcafee:asset_manager';

register_product( cpe:cpe, location:mamPort + '/tcp', port:mamPort, service:"www" );

log_message( data: build_detection_report(app:"McAfee Asset Manager",
                                         version:mamVer[1],
                                         install:mamPort + '/tcp',
                                         cpe:cpe,
                                         concluded: mamVer[0] ),
                                         port:mamPort );

exit( 0 );
