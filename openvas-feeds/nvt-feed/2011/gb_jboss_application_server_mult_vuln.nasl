# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801987");
  script_version("2023-09-06T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-06 05:05:19 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2008-3273", "CVE-2010-1429");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Red Hat JBoss Products Multiple Vulnerabilities (status page) - Active Check");

  script_category(ACT_GATHER_INFO); # nb: No access because we're "just" accessing a URL

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_red_hat_jboss_prds_http_detect.nasl", "gb_red_hat_jboss_eap_http_detect.nasl",
                      "sw_redhat_wildfly_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("redhat/jboss/prds/http/detected");

  script_tag(name:"summary", value:"Red Hat JBoss products are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to the following:

  - A publicly accessible status page. This leads to leakage of logs of last connections and (in
  second case) leakage of all services (with their paths) on the server.

  - There is no protection against Brute Force attacks at these resources and other private
  resources with BF vulnerability. The list of all resources of concrete server can be found at
  page status?full=true.

  Note: CVE-2010-1429 exists because of a CVE-2008-3273 regression.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to access
  sensitive information like e.g. services with their paths on the server.");

  script_tag(name:"affected", value:"Red Hat JBoss Application Server (AS) as used by e.g. Red Hat
  JBoss Enterprise Application Platform (EAP).");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Sep/139");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:redhat:jboss_application_server",
                      "cpe:/a:redhat:jboss_enterprise_application_platform",
                      "cpe:/a:redhat:jboss_wildfly_application_server" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"www", first_cpe_only:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
port = infos["port"];

if( ! dir = get_app_location( cpe:cpe, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/status?full=true";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( ( "Application list" >< res && "WebCCReports" >< res && "PortComponentLinkServlet" >< res ) ||
    ( "<title>Tomcat Status" >< res && "Application list" >< res && "Processing time:" >< res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
