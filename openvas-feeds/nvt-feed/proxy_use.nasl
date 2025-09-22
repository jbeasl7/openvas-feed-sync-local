# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100083");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Proxy Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl", "smtp_settings.nasl");
  script_require_ports("Services/http_proxy", 3128, 8080, 6588, 8000, 8888, "Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Limit access to the proxy to valid users and/or valid hosts.");

  script_tag(name:"summary", value:"A HTTP proxy server is running at this Host and accepts
  unauthenticated requests from the scanner.");

  script_tag(name:"insight", value:"An open proxy is a proxy server that is accessible by any
  Internet user. Generally, a proxy server allows users within a network group to store and
  forward Internet services such as DNS or web pages to reduce and control the bandwidth used
  by the group. With an open proxy, however, any user on the Internet is able to use this
  forwarding service.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("smtp_func.inc");

ports = make_list();
proxy_ports = service_get_ports( default_port_list:make_list( 3128, 8080, 6588, 8000, 8888 ), proto:"http_proxy" );
http_ports = service_get_ports( default_port_list:make_list( 80, 443 ), proto:"www" );

if( proxy_ports )
  ports = make_list( ports, proxy_ports );

if( http_ports )
  ports = make_list_unique( ports, http_ports );

vt_strings = get_vt_strings();
domain = get_3rdparty_domain();
pattern = vt_strings["lowercase"];

url = "http://" + domain + "/" + pattern + '-proxy-test';

foreach port( ports ) {

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( ! buf )
    continue;

  if( "%%" + pattern + "-proxy-test%%" >< buf ) {

    set_kb_item( name:"Proxy/usage", value:TRUE );
    set_kb_item( name:"Services/http_proxy", value:port );

    if( VIA = egrep( pattern:"^Via:.*$", string:buf ) ) {
      if( VIA = eregmatch( pattern:"^Via: (.*)$", string:VIA ) ) {
        set_kb_item( name:"Proxy/" + port  + "/via", value:chomp( VIA[1] ) );
      }
    }
    log_message( port:port );
  }
}

exit( 0 );
