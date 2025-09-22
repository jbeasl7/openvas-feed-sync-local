# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108760");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-04-29 07:29:36 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cloudflare '/cdn-cgi/trace' Debug / Trace Output Accessible (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://developers.cloudflare.com/fundamentals/reference/cdn-cgi-endpoint/");

  script_tag(name:"summary", value:"The remote host is exposing the '/cdn-cgi/trace' endpoint of
  Cloudflare via HTTP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/cdn-cgi/trace";
buf = http_get_cache( item:url, port:port );

if( buf && buf =~ "^HTTP/1\.[01] 200" &&
    buf =~ "content-type\s*:\s*text/plain" &&
    egrep( string:buf, pattern:"^visit_scheme=.+", icase:FALSE ) ) {

  report = "Exposed URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  body = http_extract_body_from_response( data:buf );
  body = chomp( body );
  if( body )
    report += '\nExposed info:\n' + body;

  log_message( port:port, data:report );
}

exit( 0 );
