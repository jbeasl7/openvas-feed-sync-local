# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16338");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mailman Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                       "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Mailman.");

  script_xref(name:"URL", value:"http://www.list.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

foreach dir( make_list_unique( "/mailman", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  foreach url( make_list( "/listinfo", "/listinfo.cgi", "/listinfo.py" ) ) {

    url = dir + url;

    res = http_get_cache( item:url, port:port );

    if( res =~ "alt=.Delivered by Mailman" ) {
      version = "unknown";
      concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      # <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.5</td>
      vers = eregmatch( pattern:'alt=.Delivered by Mailman.[^\r\n]+>version ([^<]+)', string:res );
      if( ! isnull( vers[1] ) )
        version = chomp( vers[1] );

      set_kb_item( name:"gnu_mailman/detected", value:TRUE );
      set_kb_item( name:"gnu_mailman/http/detected", value:TRUE );

      os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                              desc:"Mailman Detection (HTTP)" );

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:gnu:mailman:" );
      if( ! cpe )
        cpe = "cpe:/a:gnu:mailman";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Mailman", version:version, install:install, cpe:cpe,
                                                concludedUrl:concUrl, concluded:vers[0] ),
                   port:port );
      exit(0);
    }
  }
}

exit( 0 );
