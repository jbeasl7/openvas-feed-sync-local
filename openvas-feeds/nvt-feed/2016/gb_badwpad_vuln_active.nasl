# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105845");
  script_version("2024-04-05T15:38:49+0000");
  script_tag(name:"last_modification", value:"2024-04-05 15:38:49 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2016-08-05 14:58:54 +0200 (Fri, 05 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Web Proxy Auto-Discovery Protocol Information Disclosure Vulnerability (badWPAD) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The Web Proxy Auto-Discovery Protocol (WPAD) is a method used
  by clients to locate the URL of a configuration file using DHCP and/or DNS discovery methods.
  Once detection and download of the configuration file is complete, it can be executed to
  determine the proxy for a specified URL.

  There are known security issues with WPAD.");

  script_tag(name:"solution", value:"Apply the mentioned steps in the referenced advisory to
  mitigate the issue.");

  script_xref(name:"URL", value:"https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/badwpad-menace-of-a-bad-protocol");
  script_xref(name:"URL", value:"https://documents.trendmicro.com/assets/wp/wp-badwpad.pdf");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/wpad.dat";

req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "Content-Type: application/x-ns-proxy-autoconfig" >< res && "FindProxyForURL" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
