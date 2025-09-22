# SPDX-FileCopyrightText: 2003 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11213");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("HTTP Debugging Methods (TRACE/TRACK) Enabled");
  script_cve_id("CVE-2003-1567", "CVE-2004-2320", "CVE-2004-2763", "CVE-2005-3398", "CVE-2006-4683",
                "CVE-2007-3008", "CVE-2008-7253", "CVE-2009-2823", "CVE-2010-0386", "CVE-2012-2223",
                "CVE-2014-7883");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 E-Soft Inc.");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/288308");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15222");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/19915");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24456");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36956");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36990");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9561");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/867593");
  script_xref(name:"URL", value:"https://httpd.apache.org/docs/current/en/mod/core.html#traceenable");
  script_xref(name:"URL", value:"https://techcommunity.microsoft.com/t5/iis-support-blog/http-track-and-trace-verbs/ba-p/784482");
  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Cross_Site_Tracing");

  script_tag(name:"summary", value:"The remote web server supports the TRACE and/or TRACK
  methods. TRACE and TRACK are HTTP methods which are used to debug web server connections.");

  script_tag(name:"vuldetect", value:"Checks if HTTP methods such as TRACE and TRACK are
  enabled and can be used.");

  script_tag(name:"insight", value:"It has been shown that web servers supporting this methods
  are subject to cross-site-scripting attacks, dubbed XST for Cross-Site-Tracing, when used in
  conjunction with various weaknesses in browsers.");

  script_tag(name:"impact", value:"An attacker may use this flaw to trick your legitimate web
  users to give him their credentials.");

  script_tag(name:"affected", value:"Web servers with enabled TRACE and/or TRACK methods.");

  script_tag(name:"solution", value:"Disable the TRACE and TRACK methods in your web server
  configuration.

  Please see the manual of your web server or the references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
if( ! banner = http_get_remote_headers( port:port ) )
  exit( 0 );

vt_strings = get_vt_strings();

report = "The web server has the following HTTP methods enabled:";
file   = "/" + vt_strings["lowercase_rand"] + ".html"; # Does not exist
cmd1   = http_get( item:file, port:port );
cmd2   = cmd1;
cmd1   = ereg_replace( pattern:"GET /", string:cmd1, replace:"TRACE /" );
cmd2   = ereg_replace( pattern:"GET /", string:cmd2, replace:"TRACK /" );
ua     = egrep( pattern:"^User-Agent", string:cmd1 );

res = http_keepalive_send_recv( port:port, data:cmd1, bodyonly:TRUE );
if( res ) {
  if( egrep( pattern:"^TRACE " + file + " HTTP/1\.", string:res ) ) {
    if( ! ua || ( ua && ua >< res ) ) {
      VULN = TRUE;
      report += " TRACE";
      expert_info += 'Request:\n' + cmd1;
      expert_info += 'Response (Body):\n' + res;
    }
  }
}

res = http_keepalive_send_recv( port:port, data:cmd2, bodyonly:TRUE );
if( res ) {
  if( egrep( pattern:"^TRACK " + file + " HTTP/1\.", string:res ) ) {
    if( ! ua || ( ua && ua >< res ) ) {
      VULN = TRUE;
      report += " TRACK";
      expert_info += 'Request:\n' + cmd2;
      expert_info += 'Response (Body):\n' + res;
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report, expert_info:expert_info );
  exit( 0 );
}

exit( 99 );