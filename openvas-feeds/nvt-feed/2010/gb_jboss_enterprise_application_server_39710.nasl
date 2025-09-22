# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100610");
  script_version("2024-07-01T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:38 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 17:24:36 +0000 (Fri, 28 Jun 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-0738", "CVE-2010-1428", "CVE-2010-1429");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Red Hat JBoss Products Multiple Vulnerabilities (jmx-console) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_red_hat_jboss_prds_http_detect.nasl", "gb_red_hat_jboss_eap_http_detect.nasl",
                      "sw_redhat_wildfly_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("redhat/jboss/prds/http/detected");

  script_tag(name:"summary", value:"Red Hat JBoss products are prone to multiple vulnerabilities,
  including an information-disclosure issue and multiple authentication-bypass issues.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP PUT request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to bypass certain security
  restrictions to obtain sensitive information or gain unauthorized access to the application.");

  script_tag(name:"affected", value:"Red Hat JBoss Application Server (AS) as used by e.g. Red Hat
  JBoss Enterprise Application Platform (EAP).");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39710");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
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

url = dir + "/jmx-console";
buf = http_get_cache( item:url, port:port );
if( ! buf || buf =~ "^HTTP/1\.[01] [23]00" )
  exit( 0 );

url = dir + "/jmx-console/checkJNDI.jsp";
host = http_host_name( port:port );

req = http_post_put_req( port:port, url:url, method:"PUT" );
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && "JNDI Check</title>" >< res && "JNDI Checking for host" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
