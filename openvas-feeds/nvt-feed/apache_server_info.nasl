# SPDX-FileCopyrightText: 2005 StrongHoldNet
# SPDX-FileCopyrightText: New NASL / detection code since 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10678");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache HTTP Server /server-info Accessible (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 StrongHoldNet / 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://httpd.apache.org/docs/current/mod/mod_info.html");

  script_tag(name:"summary", value:"Requesting the URI /server-info provides a comprehensive
  overview of the server configuration.");

  script_tag(name:"insight", value:"server-info is a Apache HTTP Server handler provided by the
  'mod_info' module and used to retrieve the server's configuration.");

  script_tag(name:"impact", value:"Requesting the URI /server-info gives throughout information
  about the currently running Apache to an attacker.");

  script_tag(name:"affected", value:"All Apache installations with an enabled 'mod_info' module.");

  script_tag(name:"vuldetect", value:"Checks if the /server-info page of Apache is accessible.");

  script_tag(name:"solution", value:"- If this feature is unused commenting out the appropriate
  section in the web servers configuration is recommended.

  - If this feature is used restricting access to trusted clients is recommended.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/server-info";

buf = http_get_cache( item:url, port:port );

# e.g.
# <body><h1 style="text-align: center">Apache Server Information</h1>
# <title>Server Information</title>
if( buf && buf =~ "^HTTP/1\.[01] 200" &&
    ( ">Apache Server Information<" >< buf || "<title>Server Information</title>" >< buf ) ) {

  set_kb_item( name:"apache/server-info/detected", value:TRUE );
  set_kb_item( name:"apache/server-info/" + port + "/detected", value:TRUE );
  set_kb_item( name:"mod_jk_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"mod_perl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"mod_python_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"mod_ssl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"openssl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"perl_or_apache_status_info_error_pages/banner", value:TRUE );
  set_kb_item( name:"python_or_apache_status_info_error_pages/banner", value:TRUE );

  # <strong>Server Version:</strong> <font size="+1"><tt>Apache/2.4.38 (Raspbian) OpenSSL/1.1.1d</tt></font></dt>
  sv = eregmatch( pattern:'Server Version:([ /<>a-zA-Z0-9+="]+)<tt>([^<]+)</tt>', string:buf );
  if( sv[2] ) {
    # nb: Saving it into this format for all VTs checking something like "Server\s*:\s*Apache".
    set_kb_item( name:"www/server-info/banner/" + port, value:"Server: " + chomp( sv[2] ) );

    # nb: Used for the "Concluded" reporting in the VTs evaluating the string above to avoid
    # confusion on the "Server: " banner.
    set_kb_item( name:"www/server-info/banner/concluded/" + port, value:chomp( sv[0] ) );
  }

  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
