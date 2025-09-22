# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atutor:atutor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19765");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-2954");

  script_name("ATutor password reminder SQL injection");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("gb_atutor_detect.nasl");
  script_mandatory_keys("atutor/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://retrogod.altervista.org/atutor151.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14831");

  script_tag(name:"solution", value:"Upgrade to ATutor 1.5.1 pl1 or later.");

  script_tag(name:"summary", value:"The remote version of ATutor contains an input validation flaw in
  the 'password_reminder.php' script. This vulnerability occurs only when 'magic_quotes_gpc' is set to
  off in the 'php.ini' configuration file.");

  script_tag(name:"impact", value:"A malicious user can exploit this flaw to manipulate SQL queries and steal
  any user's password.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vtstrings = get_vt_strings();
postdata = string( "form_password_reminder=true&", "form_email=%27", vtstrings["lowercase"], "&", "submit=Submit" );

url = dir + "/password_reminder.php";
host = http_host_name( port:port );

req = string( "POST ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(postdata), "\r\n",
              "\r\n",
              postdata );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "mysql_fetch_assoc(): supplied argument is not a valid MySQL result resource" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
