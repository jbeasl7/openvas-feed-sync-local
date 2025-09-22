# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113692");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-05-20 12:00:00 +0200 (Wed, 20 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cherokee Web Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't add a Cherokee/banner script_mandatory_keys because the VT is also doing a detection
  # based on a 404 error page.

  script_tag(name:"summary", value:"HTTP based detection of the Cherokee Web Server.");

  script_xref(name:"URL", value:"https://cherokee-project.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

banner = http_get_remote_headers( port: port );

# Server: Cherokee/0.2.7
# Server: Cherokee
# Server: Cherokee/0.99.39 (Gentoo Linux)
# Server: Cherokee/1.2.103 (Arch Linux)
if( banner && concl = egrep( string: banner, pattern: "^Server\s*:\s*Cherokee", icase: TRUE ) ) {

  concluded = chomp( concl );
  version = "unknown";
  detected = TRUE;

  vers = eregmatch( string: banner, pattern: "Server\s*:\s*Cherokee/([0-9.]+)", icase: TRUE );
  if( ! isnull( vers[1] ) )
    version = vers[1];
}

if( ! version || version == "unknown" ) {

  # nb: Proxies could prevent us from getting the desired banner information.
  # But Cherokee's 404 page announces the installed version, so we can use that.

  foreach url( make_list( "/", "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

    res = http_get_cache( item: url, port: port, fetch404: TRUE );
    if( res && res =~ "^HTTP/1\.[01] [3-5][0-9]{2}" ) {

      # <p><hr>
      # Cherokee web server 1.2.101 (UNIX), Port 443
      # </body>
      if( concl = egrep( string: res, pattern: "Cherokee web server.*, Port [0-9]+", icase: FALSE ) ) {

        version = "unknown";
        detected = TRUE;
        conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );

        concl = chomp( concl );
        if( concluded )
          concluded += '\n';
        concluded += concl;

        vers = eregmatch( pattern: "Cherokee web server ([0-9.]+)", string: concl, icase: FALSE );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Cherokee/" + version );
        } else {
          replace_kb_item( name: "www/real_banner/" + port + "/", value: "Server: Cherokee" );
        }

        break;
      }
    }
  }
}

if( detected ) {

  set_kb_item( name: "cherokee/detected", value: TRUE );
  set_kb_item( name: "cherokee/http/detected", value: TRUE );

  # nb:
  # - To tell http_can_host_php from http_func.inc that the service is supporting this
  # - Product can definitely host PHP scripts (via some PHP-fpm/FastCGI integration)
  # - TBD: replace_kb_item( name: "www/" + port + "/can_host_asp", value: "yes" ); ?
  replace_kb_item( name: "www/" + port + "/can_host_php", value: "yes" );

  register_and_report_cpe( app: "Cherokee Web Server",
                           ver: version,
                           concluded: concluded,
                           base: "cpe:/a:cherokee-project:cherokee:",
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www",
                           conclUrl: conclurl );
}

exit( 0 );
