# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900498");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache HTTP Server Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl",
                      "apache_server_info.nasl", "apache_server_status.nasl",
                      "gb_apache_perl_status.nasl", "gb_apache_http_server_http_error_page_detect.nasl");
                      # nb: The ones above are also setting an Apache banner/version into the KB (if
                      # e.g. the banner itself or only the version was hidden but the pages are
                      # still accessible.
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't add a apache/http_server/banner script_mandatory_keys because the VT is also doing a
  # detection based on a specific status or 404 error pages.

  script_tag(name:"summary", value:"HTTP based detection of the Apache HTTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

# Just the default server banner like:
# Server: Apache
# Server: Apache/1.3.34 (Unix) mod_jk/1.2.15
# Server: Apache/2.4.2 (Unix) PHP/4.2.2 MyMod/1.2
# Server: Apache/2.4.43 (Linux/SUSE) OpenSSL/1.1.1d
# Server: Apache/2.4.43
# nb: The "ServerTokens" might be set to "Major" or "Minor" which are reporting the
# following banner:
# Server: Apache/2
# Server: Apache/2.4
#
# some older variants (which seems to be some forks) are:
# Server: Rapidsite/Apa-1.3.14 (Unix), Frontpage/4.0.4.3, mod_ssl/2.7.1, OpenSSL/0.9.5a
# Server: Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
#
# nb: The pattern below also needs to make sure that we're not catching things like e.g.:
# Server: Apache Tomcat
# Server: Apache-Coyote/1.1
# Server: Apache Tomcat/4.1.12 (HTTP/1.1 Connector)
# Server: apachejserv/1.0.1
base_pattern = "^Server\s*:\s(Apache(-AdvancedExtranetServer)?($|/)|Rapidsite/Apa)"; # nb: Keep in sync with the pattern in gb_get_http_banner.nasl.
version_pattern = "(Apache(-AdvancedExtranetServer)?/|Rapidsite/Apa-)([0-9.]+(-(alpha|beta))?)";

server_banner = egrep( pattern:"^Server\s*:.+apa", string:banner, icase:TRUE );
if( server_banner ) {
  # nb: Just strip any trailing newlines from the egrep() return above so that we can use a
  # "$" in the "base_pattern" pattern without having to take care of "\r\n" and similar.
  server_banner = chomp( server_banner );
}

if( server_banner && concl = egrep( string:server_banner, pattern:base_pattern, icase:TRUE ) ) {

  concluded = chomp( concl );
  version = "unknown";
  detected = TRUE;

  vers = eregmatch( pattern:"Server\s*:\s*" + version_pattern, string:server_banner, icase:TRUE );
  if( ! isnull( vers[3] ) )
    version = vers[3];
}

if( ! version || version == "unknown" ) {

  # From apache_server_info.nasl, apache_server_status.nasl or gb_apache_perl_status.nasl
  foreach infos( make_list( "server-info", "server-status", "perl-status" ) ) {

    info = get_kb_item( "www/" + infos + "/banner/" + port );
    if( info ) {

      version = "unknown";
      detected = TRUE;

      conclurl = http_report_vuln_url( port:port, url:"/" + infos, url_only:TRUE );

      info = chomp( info );
      if( concluded )
        concluded += '\n';
      concluded += info;

      vers = eregmatch( pattern:"Server\s*:\s*" + version_pattern, string:info, icase:TRUE );
      if( ! isnull( vers[3] ) ) {
        version = vers[3];
        replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: " + vers[1] + version );
      } else {
        replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
      }

      break;
    }
  }
}

if( ! version || version == "unknown" ) {

  # nb: From gb_apache_http_server_http_error_page_detect.nasl. This might have either:
  # Server: Apache
  # Server: Apache/1.2.3
  # or even the following if changed by e.g. mod_security:
  # Server: MyChangedBanner
  # For the last case the eregmatch() below is used to set / gather the correct version.
  if( concl = get_kb_item( "www/apache_error_page/banner/" + port ) ) {

    version = "unknown";
    detected = TRUE;

    if( url = get_kb_item( "www/apache_error_page/banner/location/" + port ) ) {
      if( conclurl )
        conclurl += '\n';
      conclurl += http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    concl = chomp( concl );
    if( concluded )
      concluded += '\n';
    concluded += concl;

    vers = eregmatch( pattern:"Server\s*:\s*" + version_pattern, string:concl, icase:TRUE );
    if( ! isnull( vers[3] ) ) {
      version = vers[3];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: " + vers[1] + version );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
    }
  }
}

if( ! version || version == "unknown" ) {

  # nb: A few systems have the documentation at the root dir so checking both.
  foreach url( make_list( "/manual/en/index.html", "/" ) ) {

    res = http_get_cache( item:url, port:port );

    # From the apache docs, this is only providing the major release (e.g. 2.4)
    # e.g. (in two lines)
    # <title>Apache HTTP Server Version 2.2
    # Documentation - Apache HTTP Server</title>
    #
    # <title>Apache HTTP Server Version 2.4
    # Documentation - Apache HTTP Server Version 2.4</title>
    if( res && res =~ "^HTTP/1\.[01] 200" && "Documentation - Apache HTTP Server" >< res && concl = egrep( string:res, pattern:"<title>Apache HTTP Server Version", icase:TRUE ) ) {

      version = "unknown";
      detected = TRUE;

      if( conclurl )
        conclurl += '\n';
      conclurl += http_report_vuln_url( port:port, url:url, url_only:TRUE );

      concl = chomp( concl );
      if( concluded )
        concluded += '\n';
      concluded += concl;

      vers = eregmatch( pattern:"<title>Apache HTTP Server Version ([0-9.]+)", string:concl );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache/" + version );
      } else {
        replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: Apache" );
      }

      break;
    }
  }
}

if( detected ) {

  # nb:
  # - To tell http_can_host_asp and http_can_host_php from http_func.inc that the service is
  #   supporting these
  # - Product can definitely host PHP scripts
  # - Might be also used as a reverse proxy to systems able to host ASP scripts
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"yes" );

  set_kb_item( name:"apache/http_server/detected", value:TRUE );
  set_kb_item( name:"apache/http_server/http/detected", value:TRUE );
  set_kb_item( name:"apache/http_server/http/" + port + "/installs", value:port + "#---#" + port + "/tcp" + "#---#" + version + "#---#" + concluded + "#---#" + conclurl + "#---#" );
}

exit( 0 );
