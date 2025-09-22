# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117544");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2021-07-09 09:17:42 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Apache HTTP Server Detection (HTTP Error Page)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP error-page based detection of the Apache HTTP Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

# nb: No need to run if we have a full banner like e.g.:
# Server: Apache/2.4.2
# In this case we don't get any additional / more detailed info from the error page and just can jump out.
if( banner && egrep( string:banner, pattern:"^Server\s*:\s*Apache/[0-9.]+", icase:TRUE ) )
  exit( 0 );

pattern1 = "<address>(.+) Server at .+ Port [0-9]+</address>";
pattern2 = "\s*<span>(Apache[^<]*)</span>";

foreach url( make_list( "/", "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" ) ) {

  res = http_get_cache( item:url, port:port, fetch404:TRUE );
  if( ! res || res !~ "^HTTP/1\.[01] [3-5][0-9]{2}" )
    continue;

  # If the banner was hidden or was changed by e.g. mod_security but the default error
  # page still exists. e.g.:
  #
  # <address>Apache/2.4.10 (Debian) Server at <redacted> Port 80</address>
  #
  # but also:
  #
  # <address>MyChangedBanner Server at <redacted> Port 80</address>
  #
  # nb: The above default error page was seen on Debian / Ubuntu but e.g SLES 15 has a
  # different one we need to cover as well:
  #
  # <h2>Error 403</h2>
  # <address>
  #   <a href="/">127.0.0.1</a><br />
  #   <span>Apache</span>
  # </address>
  #
  # or:
  #
  # <address>
  #   <a href="/"><redacted></a><br />
  #   <span>Apache/2.4.43 (Linux/SUSE) OpenSSL/1.1.1d</span>
  # </address>
  #
  if( concl = egrep( string:res, pattern:"^" + pattern1, icase:TRUE ) ) {
    error_page_found = TRUE;
    kb_banner = eregmatch( string:concl, pattern:pattern1, icase:TRUE );
  } else if( res =~ "<address>.*<a href=.+</a>.*<span>Apache[^<]*</span>.*</address>" ) {
    error_page_found = TRUE;
    concl = egrep( string:res, pattern:"^" + pattern2, icase:TRUE );
    if( concl )
      kb_banner = eregmatch( string:concl, pattern:pattern2, icase:TRUE );
  }

  if( error_page_found ) {
    set_kb_item( name:"apache/http_server/error_page/detected", value:TRUE );
    set_kb_item( name:"www/apache_error_page/banner/location/" + port, value:url );
    set_kb_item( name:"mod_jk_or_apache_status_info_error_pages/banner", value:TRUE );
    set_kb_item( name:"mod_perl_or_apache_status_info_error_pages/banner", value:TRUE );
    set_kb_item( name:"mod_python_or_apache_status_info_error_pages/banner", value:TRUE );
    set_kb_item( name:"mod_ssl_or_apache_status_info_error_pages/banner", value:TRUE );
    set_kb_item( name:"openssl_or_apache_status_info_error_pages/banner", value:TRUE );
    set_kb_item( name:"perl_or_apache_status_info_error_pages/banner", value:TRUE );
    set_kb_item( name:"python_or_apache_status_info_error_pages/banner", value:TRUE );

    if( kb_banner[1] ) {
      # nb: Saving it into this format for all VTs checking something like "Server\s*:\s*Apache".
      set_kb_item( name:"www/apache_error_page/banner/" + port, value:"Server: " + chomp( kb_banner[1] ) );

      concluded = chomp( kb_banner[0] );
      # nb: Just to let the end-user to know that this is a Apache HTTP error page
      if( " Server at " >< concluded && "Apache" >!< concluded )
        concluded += " (Note: This is an Apache HTTP Server error page with a modified server banner)";

      # nb: Used for the "Concluded" reporting in the VTs evaluating the string above to avoid
      # confusion on the "Server: " banner.
      set_kb_item( name:"www/apache_error_page/banner/concluded/" + port, value:concluded );
    }

    break;
  }
}

exit( 0 );
