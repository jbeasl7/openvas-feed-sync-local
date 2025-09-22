# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105821");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-07-25 12:58:51 +0200 (Mon, 25 Jul 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MGate Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Moxa MGate.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/Overview.html";

res = http_get_cache( port:port, item:url );

if( ( res !~ ">Welcome to MGate.*web console" || "<title>Overview</title>" >!< res ) &&
      "&nbsp;MGate&nbsp;" >!< res)
  exit( 0 );

set_kb_item( name:"moxa/mgate/detected", value:TRUE );
set_kb_item( name:"moxa/mgate/http/detected", value:TRUE );
set_kb_item( name:"moxa/mgate/http/port", value:port );
set_kb_item( name:"moxa/mgate/http/" + port + "/concludedUrl",
             value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

res = str_replace( string:res, find:"&nbsp;", replace:" " );

lines = split( res );

version = "unknown";
build = "unknown";
model = "unknown";

for( i = 0; i < max_index( lines ); i++ ) {
  # <td width="12%">- MGate MB3270</td>
  if( lines[i] =~ ">Model( Name)?<" ) {
    mod = eregmatch( pattern:'MGate ([^<]+)<', string:lines[i+1] );
    if( ! isnull( mod[1] ) )
      model = mod[1];
  }

  # <td><li>Firmware</li></td>
  if( lines[i] =~ ">Firmware( version)?<" ) {
    vb = eregmatch( pattern:'>[^0-9]*([0-9.]+[^ ]+) Build ([0-9]+[^< ]+)<', string:lines[i+1] );
    if( ! isnull( vb[1] ) ) {
      version = vb[1];
      set_kb_item( name:"moxa/mgate/http/" + port + "/concluded", value:vb[0] );
    }

    if( ! isnull( vb[2] ) )
      build = vb[2];
  }
}

set_kb_item( name:"moxa/mgate/http/" + port + "/model", value:model );
set_kb_item( name:"moxa/mgate/http/" + port + "/version", value:version );
set_kb_item( name:"moxa/mgate/http/" + port + "/build", value:build );

exit(0);
