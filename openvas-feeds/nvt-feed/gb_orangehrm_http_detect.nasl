# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100850");
  script_version("2024-05-30T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:33 +0000 (Thu, 30 May 2024)");
  script_tag(name:"creation_date", value:"2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OrangeHRM Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.orangehrm.com");

  script_tag(name:"summary", value:"HTTP based detection of OrangeHRM.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/orangehrm", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: Newer versions use a very specific pattern
  foreach page( make_list_unique( "/login.php", "/", "/symfony/web/index.php/auth/login", "/web/index.php/auth/login" ) ) {

    url = dir + page;
    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" )
      continue;

    # Newer versions:
    # <title>OrangeHRM</title>
    # <div id="footer" >
    #     <div>
    #     OrangeHRM 4.3.1<br/>
    #     &copy; 2005 - 2019 <a href="http://www.orangehrm.com" target="_blank">OrangeHRM, Inc</a>. All rights reserved.
    #    </div>
    # but without the "Login Name:"
    #
    if( ( "<title>OrangeHRM" >< buf && "&copy; OrangeHRM Inc." >< buf && "Login Name :" >< buf ) ||
        ( buf =~ '<title>[^<]*OrangeHRM' && ( ">OrangeHRM, Inc<" >< buf || "//www.orangehrm.com" >< buf || "js/orangehrm.validate.js" >< buf || "OrangeHRM on " >< buf ) ) ) {

      vers = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      # <td align="center"><a href="http://www.orangehrm.com" target="_blank">OrangeHRM</a> ver 2.4.2 &copy; OrangeHRM Inc. 2005 - 2008 All rights reserved.</td>
      version = eregmatch( string:buf, pattern:"OrangeHRM</a> ver ([0-9.]+)", icase:TRUE );
      if( version[1] )
        vers = chomp( version[1] );

      if( vers == "unknown" ) {
        # OrangeHRM 4.3.1<br/>
        # OrangeHRM 4.3.4<br/>
        # OrangeHRM 4.8<br/>
        # OrangeHRM 3.3.2<br/>
        # OrangeHRM 4.0<br/>
        #
        # but have seen something like the following as well:
        #
        # SS HRM 3.3.1<br/>
        #
        # which was actually also an OrangeHM and which also had the "OrangeHRM" title.
        # Not sure if this is caused by some theming...
        version = eregmatch( string:buf, pattern:"(Orange| )HRM ([0-9.]+)<", icase:TRUE );
        if( version[2] )
          vers = version[2];
      }

      if( vers == "unknown" ) {
        # <oxd-text tag="p" class="orangehrm-copyright">OrangeHRM OS 5.6.1</oxd-text>
        # <oxd-text tag="p" class="orangehrm-copyright">OrangeHRM OS 5.3</oxd-text>
        version = eregmatch( string:buf, pattern:">OrangeHRM OS ([0-9.]+)", icase:TRUE );
        if( version[1] )
          vers = chomp( version[1] );
      }

      set_kb_item( name:"orangehrm/detected", value:TRUE );
      set_kb_item( name:"orangehrm/http/detected", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:orangehrm:orangehrm:" );
      if( ! cpe )
        cpe = "cpe:/a:orangehrm:orangehrm";

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"OrangeHRM",
                                                version:vers,
                                                install:install,
                                                cpe:cpe,
                                                concludedUrl:conclUrl,
                                                concluded:version[0] ),
                   port:port );
      exit( 0 );
    }
  }
}

exit( 0 );
