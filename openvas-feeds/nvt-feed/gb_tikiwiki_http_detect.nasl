# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901001");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Tiki Wiki CMS Groupware Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://tiki.org/");

  script_tag(name:"summary", value:"HTTP based detection of Tiki Wiki CMS Groupware.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/tikiwiki", "/tiki", "/wiki", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item:dir + "/tiki-index.php", port:port );

  if( 'content="Tiki Wiki CMS Groupware' >< res || '/css/tiki_base.css"' >< res || 'title="Tiki powered site"' >< res ||
                                      'href="tiki-remind_password.php"' >< res || "This is Tikiwiki " >< res || '"lib/tiki-js.js"' >< res ||
                                      '"Tikiwiki powered site"' >< res || 'img/tiki/tikilogo.png"' >< res ) {

    version = "unknown";

    # This is Tikiwiki v2.3  -Arcturus- &#169; 2002&#8211;2008 by the
    # Toto je TikiWiki v1.9.8.3  -Sirius- &#169; 2002&#8211;2007 &ndash;
    # >TikiWiki CMS/Groupware</a>  v2.2  -Arcturus-
    ver = eregmatch( pattern:"(Tiki[wW]iki v?|TikiWiki CMS/Groupware</a>\s*v)([0-9.]+)", string:res );

    if( ! isnull( ver[2] ) ) {
      version = ver[2];
    } else {
      url = dir + "/README";
      res = http_get_cache( item:url, port:port );
      if( res =~ "^HTTP/1\.[01] 200" && "Tiki" >< res ) {

        # version 2.3 -Arcturus-
        # version 2.2 (CVS) -Arcturus-
        # version 1.9.8.3 -Sirius-
        # Version 7.2
        # Version 12.2
        # Version 20.0
        #
        # all of them have the following:
        # Tiki! The wiki with a lot of features!
        ver = eregmatch( pattern:"[v|V]ersion ([0-9.]+)", string:res );
        if( ! isnull( ver[1] ) ) {
          version = ver[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    url = dir + "/tiki-install.php";
    res = http_get_cache( item:url, port:port );
    if( res =~ "^HTTP/1\.[01] 200" && "<title>Tiki Installer" >< res ) {
      extra = "The Tiki Installer is available at " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"TikiWiki/" + port + "/Ver", value:tmp_version );
    set_kb_item( name:"tiki/wiki/detected", value:TRUE );
    set_kb_item( name:"tiki/wiki/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tiki:tikiwiki_cms%2fgroupware:" );
    if( ! cpe )
      cpe = "cpe:/a:tiki:tikiwiki_cms%2fgroupware";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Tiki Wiki CMS Groupware",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
