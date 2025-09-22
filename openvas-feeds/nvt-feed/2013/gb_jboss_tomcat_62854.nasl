# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103811");
  script_version("2024-08-09T15:39:05+0000");
  script_tag(name:"last_modification", value:"2024-08-09 15:39:05 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2013-10-15 10:27:36 +0200 (Tue, 15 Oct 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:56:56 +0000 (Tue, 16 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  script_cve_id("CVE-2012-0874", "CVE-2013-4810");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object Remote Code Execution - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Apache Tomcat/JBoss Application Server is prone to multiple
  remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Determines if the EJBInvokerServlet and/or JMXInvokerServlet
  is accessible without authentication.");

  script_tag(name:"insight", value:"The specific flaw exists within the exposed EJBInvokerServlet
  and JMXInvokerServlet. An unauthenticated attacker can post a marshalled object allowing them to
  install an arbitrary application on the target server.");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow an attacker to
  execute arbitrary code within the context of the affected application. Failed exploit attempts
  may result in a denial of service condition.");

  script_tag(name:"affected", value:"Apache Tomcat/JBoss Application Server providing access to the
  EJBInvokerServlet and/or JMXInvokerServlet without prior authentication.");

  script_tag(name:"solution", value:"Ask the Vendor for an update and enable authentication for the
  mentioned servlets.");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-13-229/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57552");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62854");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/28713/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/30211");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 9200);

foreach file (make_list("/EJBInvokerServlet", "/JMXInvokerServlet")) {
  url = "/invoker" + file;

  req = http_get(port: port, item: url);
  res = http_send_recv(port: port, data: req);

  if (res =~ "^HTTP/1\.[01] 200" && "404" >!< res && "org.jboss.invocation.MarshalledValue" >< res &&
      "x-java-serialized-object" >< res && "WWW-Authenticate" >!< res)
    report += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

if (report) {
  report = 'The following Servlets are accessible without authentication which indicates that a RCE attack can be executed:\n' + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
