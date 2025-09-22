# SPDX-FileCopyrightText: 2001 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10613");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2002-1630", "CVE-2002-1631", "CVE-2002-1632");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle XSQL Sample Application Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Oracle/banner"); # The check below is quite unreliable these days so just run it against Oracle servers

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/717827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6556");

  script_tag(name:"summary", value:"One of the sample applications that comes with
  the Oracle XSQL Servlet allows an attacker to make arbitrary queries to
  the Oracle database (under an unprivileged account).");

  script_tag(name:"impact", value:"Whilst not allowing an attacker to delete or modify database
  contents, this flaw can be used to enumerate database users and view table names.");

  script_tag(name:"solution", value:"Sample applications should always be removed from
  production servers.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/xsql/demo/adhocsql/query.xsql?sql=select%20username%20from%20ALL_USERS";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "^HTTP/1\.[01] 200" && "USERNAME" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
