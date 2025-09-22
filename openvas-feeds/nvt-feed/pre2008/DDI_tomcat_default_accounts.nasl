# SPDX-FileCopyrightText: 2003 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11204");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Apache Tomcat Default Account (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the default passwords by editing the
  admin-users.xml file located in the /conf/users subdirectory of the Tomcat installation.");

  script_tag(name:"summary", value:"This host appears to be the running the Apache Tomcat
  Servlet engine with the default accounts still configured.");

  script_tag(name:"impact", value:"A potential intruder could reconfigure this service in a way
  that grants system access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

#list of default acnts base64()'d
auth[0] = "YWRtaW46Y2hhbmdldGhpcw==\r\n\r\n";
real_auth[0] = "admin:tomcat";
auth[1] = "YWRtaW46dG9tY2F0Cg==\r\n\r\n";
real_auth[1] = "admin:admin";
auth[2] = "YWRtaW46YWRtaW4K\r\n\r\n";
real_auth[2] = "tomcat:tomcat";
auth[3] = "dG9tY2F0OnRvbWNhdAo=\r\n\r\n";
real_auth[3] = "admin:tomcat";
auth[4] = "cm9vdDpyb290Cg==\r\n\r\n";
real_auth[4] = "root:root";
auth[5] = "cm9sZTE6cm9sZTEK\r\n\r\n";
real_auth[5] = "role1:role1";
auth[6] = "cm9sZTpjaGFuZ2V0aGlzCg==\r\n\r\n";
real_auth[6] = "role:changethis";
auth[7] = "cm9vdDpjaGFuZ2V0aGlzCg==\r\n\r\n";
real_auth[7] = "root:changethis";
auth[8] = "dG9tY2F0OmNoYW5nZXRoaXMK\r\n\r\n";
real_auth[8] = "tomcat:changethis";
auth[9] = "eGFtcHA6eGFtcHA=\r\n\r\n";
real_auth[9] = "xampp:xampp";

url = "/admin/contextAdmin/contextList.jsp";

basereq = http_get( item:url, port:port );
basereq = basereq - "\r\n\r\n";

authBasic = "Authorization: Basic ";

i = 0;
found = 0;
report = "";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! ereg( pattern:"^HTTP/1\.[01] 401 ", string:buf ) )
  exit( 0 );

if( "<title>Context list</title>" >< buf || "<title>Context Admin</title>" >< buf )
  exit( 0 );

while( auth[i] ) {

  t0 = basereq;
  t1 = authBasic;
  t1 = t1 + auth[i];
  t0 = t0 + t1;

  buf = http_keepalive_send_recv( port:port, data:t0, bodyonly:FALSE );

  if( "<title>Context list</title>" >< buf || "<title>Context Admin</title>" >< buf ) {
    found++;
    if( found == 1 ) {
      accounts = "The following accounts were discovered: \n" + real_auth[i] + "\n";
    } else {
      accounts = accounts + real_auth[i] + "\n";
    }
  }
  i++;
}

if( found ) {
  report = http_report_vuln_url( port:port, url:url );
  report += '\n\n' + accounts;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
