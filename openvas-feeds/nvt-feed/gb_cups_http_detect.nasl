# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900348");
  script_version("2024-10-09T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-10-09 05:05:35 +0000 (Wed, 09 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apple / OpenPrinting CUPS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 631);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Common Unix Printing System (CUPS).");

  script_xref(name:"URL", value:"https://www.cups.org/");
  script_xref(name:"URL", value:"https://openprinting.github.io/cups");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:631 );

url = "/";
res = http_get_cache( port:port, item:url );

# Server: CUPS/1.1
# Server: CUPS/1.4
# Server: CUPS/2.2 IPP/2.1
# Server: CUPS/1.7 IPP/2.1
if( concl = egrep( string:res, pattern:"^Server\s*:\s*CUPS/", icase:TRUE ) ) {
  found = TRUE;
  concluded = "  " + chomp( concl );
}

# <TITLE>Forbidden - CUPS v2.4.6</TITLE>
# <title>Home - CUPS 2.3.1</title>
# <TITLE>Bad Request - CUPS v2.3.1</TITLE>
# <TITLE>403 Forbidden</TITLE>
# <TITLE>Web Interface is Disabled - CUPS v2.0.3</TITLE>
# <TITLE>Not Found - CUPS v1.5.4</TITLE>
# <TITLE>Not Found - CUPS v2.3.3</TITLE>
# <TITLE>Home - CUPS 1.6.3</TITLE>
#
# nb: When adding additional strings here make sure to also update the check in sw_http_os_detection.nasl
#
if( concl = eregmatch( string:res, pattern:"<TITLE>(Forbidden|Home|Not Found|Bad Request|Web Interface is Disabled) - CUPS.*</TITLE>", icase:TRUE ) ) {
  found = TRUE;
  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];
}

if( found ) {

  version = "unknown";
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  install = url;

  # nb: No need to add those to the "concluded" string as both are already included there
  vers = eregmatch( pattern:"<title>.*CUPS v?([0-9.RCB]+).*</title>", string:res, icase:TRUE );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
  } else {
    vers = eregmatch( pattern:"Server\s*:\s*CUPS/([0-9.RCB]+)", string:res, icase:TRUE );
    if( ! isnull( vers[1] ) )
      version = vers[1]; # nb: Only getting the major version here
  }

  set_kb_item( name:"cups/detected", value:TRUE );
  set_kb_item( name:"cups/http/detected", value:TRUE );

  # nb: sw_http_os_detection.nasl has already OS detection support but we're adding this just to be sure...
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Apple / OpenPrinting CUPS Detection (HTTP)", runs_key:"unixoide" );

  # nb: CUPS for iOS, iPadOS and macOS is developed by Apple, while for Linux and other platforms by OpenPrinting, since 2020.
  cpe1 = build_cpe( value:version, exp:"^([0-9.]+)([a-z0-9]+)?", base:"cpe:/a:apple:cups:" );
  cpe2 = build_cpe( value:version, exp:"^([0-9.]+)([a-z0-9]+)?", base:"cpe:/a:openprinting:cups:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:apple:cups";
    cpe2 = "cpe:/a:openprinting:cups";
  }

  register_product( cpe:cpe1, location:install, port:port, service:"www" );
  register_product( cpe:cpe2, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Apple / OpenPrinting CUPS",
                                            version:version,
                                            install:install,
                                            port:port,
                                            cpe:cpe1,
                                            concludedUrl:conclUrl,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
