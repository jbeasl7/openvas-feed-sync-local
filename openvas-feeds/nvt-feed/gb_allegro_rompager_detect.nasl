# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:allegrosoft:rompager:";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105153");
  script_version("2025-07-17T05:43:33+0000");
  script_name("Allegro RomPager Detection (HTTP)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2014-12-23 10:00:24 +0100 (Tue, 23 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Allegro/banner");

  script_tag(name:"summary", value:"HTTP based detection of Allegro RomPager.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

url = "/Allegro";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( concl = egrep( string:buf, pattern:"(RomPager Advanced Version|^Server\s*:\s*(Allegro-Software-)?RomPager)", icase:TRUE ) ) {

  concl = chomp( concl );
  version = "unknown";

  set_kb_item( name:"allegro/rompager/detected", value:TRUE );
  set_kb_item( name:"allegro/rompager/http/detected", value:TRUE );

  vers = eregmatch( string:buf, pattern:"RomPager/([0-9][0-9a-z.]+)" );
  if( isnull( vers[1] ) )
    vers = eregmatch( string:buf, pattern:"RomPager Advanced Version ([0-9.]+)" );

  if( ! isnull( version[1] ) )
    version = chomp( vers[1] );

  register_and_report_cpe( app:"Allegro RomPager",
                           ver:version,
                           concluded:concl,
                           base:CPE,
                           expr:"([0-9.]+)([0-9a-z.-]+)?",
                           insloc:port + "/tcp",
                           regPort:port,
                           regService:"www" );
}

exit( 0 );
