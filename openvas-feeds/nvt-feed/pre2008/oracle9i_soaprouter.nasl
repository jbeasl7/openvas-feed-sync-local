# SPDX-FileCopyrightText: 2003 Javier Fernandez-Sanguino
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11227");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1371");
  script_name("Oracle 9iAS SOAP Default Configuration Vulnerability (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Javier Fernandez-Sanguino");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/ias_soap_alert.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4289");
  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-08.html");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/476619");
  script_xref(name:"URL", value:"http://www.nextgenss.com/papers/hpoas.pdf");

  script_tag(name:"solution", value:"Disable SOAP or the deploy/undeploy feature by editing:

  $ORACLE_HOME/Apache/Jserver/etc/jserv.conf

  and removing/commenting the following four lines:

  ApJServGroup group2 1 1 $ORACLE_HOME/Apache/Jserv/etc/jservSoap.properties

  ApJServMount /soap/servlet ajpv12://localhost:8200/soap

  ApJServMount /dms2 ajpv12://localhost:8200/soap

  ApJServGroupMount /soap/servlet balance://group2/soap

  Note that the port number might be different from 8200. Also, you will need to change in the file:

  $ORACLE_HOME/soap/werbapps/soap/WEB-INF/config/soapConfig.xml:

  <osc:option name='autoDeploy' value='true' />

  to

  <osc:option name='autoDeploy' value='false' />");

  script_tag(name:"summary", value:"In a default installation of Oracle 9iAS v.1.0.2.2, it is possible to
  deploy or undeploy SOAP services without the need of any kind of credentials.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"This is due to SOAP being enabled by default after installation in
  order to provide a convenient way to use SOAP samples. However, this feature poses a threat to HTTP
  servers with public access since remote attackers can create soap services and then invoke them remotely.
  Since SOAP services can contain arbitrary Java code in Oracle 9iAS this means that an attacker can
  execute arbitrary code in the remote server.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/soap/servlet/soaprouter";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if(res && "SOAP Server" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
