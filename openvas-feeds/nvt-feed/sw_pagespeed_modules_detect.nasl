# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111099");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-05-03 17:00:00 +0200 (Tue, 03 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PageSpeed Modules (mod_pagespeed/ngx_pagespeed) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify the
  PageSpeed Modules (mod_pagespeed/ngx_pagespeed) from the server banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

if( "x-mod-pagespeed" >< tolower( banner ) ) {

  version = "unknown";

  set_kb_item( name:"mod_pagespeed/installed", value:TRUE );

  ver = eregmatch( string:banner, pattern:"X-Mod-Pagespeed: ([0-9.\-]+)", icase:TRUE );
  if( ver[1] ) version = ver[1];

  cpe = build_cpe( value: version, exp:"^([0-9.\-]+)", base:"cpe:/a:google:mod_pagespeed:" );
  if( ! cpe )
    cpe = "cpe:/a:google:mod_pagespeed";

  register_product( cpe:cpe, location:port + "/tcp", port:port, service:"www" );

  log_message( data:build_detection_report( app:"mod_pagespeed",
                                            version:version,
                                            install:port + "/tcp",
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

if( "x-page-speed" >< tolower( banner ) ) {

  version = "unknown";

  set_kb_item( name:"ngx_pagespeed/installed", value:TRUE );

  ver = eregmatch( string:banner, pattern:"X-Page-Speed: ([0-9.\-]+)", icase:TRUE );
  if( ver[1] ) version = ver[1];

  cpe = build_cpe( value: version, exp:"^([0-9.\-]+)", base:"cpe:/a:google:ngx_pagespeed:" );
  if( ! cpe )
    cpe = "cpe:/a:google:ngx_pagespeed";

  register_product( cpe:cpe, location:port + "/tcp", port:port, service:"www" );

  log_message( data:build_detection_report( app:"ngx_pagespeed",
                                            version:version,
                                            install:port + "/tcp",
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
