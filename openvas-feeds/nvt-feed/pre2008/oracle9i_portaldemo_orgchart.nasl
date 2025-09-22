# SPDX-FileCopyrightText: 2003 Frank Berger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11918");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1193");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Oracle 9iAS PORTAL_DEMO ORG_CHART");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Frank Berger");
  script_family("Web application abuses");
  script_dependencies("gb_oracle_app_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oracle/http_server/detected");

  script_xref(name:"URL", value:"http://otn.oracle.com/deploy/security/pdf/2003alert61_2.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8966");

  script_tag(name:"solution", value:"Remove the Execute for Public grant from the PL/SQL package in schema
  PORTAL_DEMO (REVOKE execute ON portal_demo.org_chart FROM public, ).

  Please check also Oracle Security Alert 61 for patch-information.");

  script_tag(name:"summary", value:"In your installation of Oracle 9iAS, it is possible to access
  a demo (PORTAL_DEMO.ORG_CHART) via mod_plsql. Access to these pages should
  be restricted, because it may be possible to abuse this demo for
  SQL Injection attacks.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

# Make a request for the Admin_ interface.
url = "/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if( "Organization Chart" >< res ) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
