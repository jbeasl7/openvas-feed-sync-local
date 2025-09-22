# Copyright (C) 2010 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900242");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HP OpenView Network Node Manager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 7510);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of HP OpenView Network
  Node Manager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:7510 );

req = http_get( item:"/topology/home", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ( "Network Node Manager Home Base" >< res || "hp OpenView Network Node Manager" >< res ) &&
      egrep( pattern:"Copyright \(c\).* Hewlett-Packard", string:res ) &&
      res =~ "HTTP/1\.. 200" ) {

  version = "unknown";
  install = "/";

  ## Extract Version from the response and set the KB
  vers = eregmatch( pattern:">NNM Release ([0-9a-zA-Z\.]+)<", string:res );

  if( vers != NULL ) {
    version = vers[1];
    set_kb_item( name:"www/"+ port + "/HP/OVNNM/Ver", value:version );
  }

  set_kb_item( name:"HP/OVNNM/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:hp:openview_network_node_manager:" );
  if( ! cpe )
    cpe = 'cpe:/a:hp:openview_network_node_manager';

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"HP OpenView Network Node Manager",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
