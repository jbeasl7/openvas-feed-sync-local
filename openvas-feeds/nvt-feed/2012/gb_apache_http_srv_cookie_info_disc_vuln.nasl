# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902830");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2012-0053");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-04-26 12:12:12 +0530 (Thu, 26 Apr 2012)");
  script_name("Apache HTTP Server 'httpOnly' Cookie Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.");

  script_tag(name:"affected", value:"Apache HTTP Server versions 2.2.0 through 2.2.21.");

  script_tag(name:"insight", value:"The flaw is due to an error within the default error response for
  status code 400 when no custom ErrorDocument is configured, which can be
  exploited to expose 'httpOnly' cookies.");

  script_tag(name:"solution", value:"Update to Apache HTTP Server version 2.2.22 or later.");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a cookie information disclosure vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47779");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51706");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18442");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2012-0128.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1235454");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2012-02/msg00026.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

exp = crap(820);

for(i=0; i<10; i++) {
  cookie += "c"+ i + "=" + exp + "; path=/; ";
}

host = http_host_name(port:port);

req = string( "GET / HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "Cookie: ", cookie, "\r\n\r\n" );

res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(res && "400 Bad Request" >< res &&
   res =~ "Cookie: c[0-9]=X{820}; path=/;" &&
   "Size of a request header field exceeds server limit" >< res){
  security_message(port:port);
  exit(0);
}

exit(99);