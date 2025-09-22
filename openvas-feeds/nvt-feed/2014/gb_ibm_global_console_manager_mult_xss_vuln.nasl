# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804775");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-3080", "CVE-2014-3081", "CVE-2014-3085");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-10-13 16:48:44 +0530 (Mon, 13 Oct 2014)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("IBM Global Console Manager Switches Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"IBM Global Console Manager switches are prone to multiple
  cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user-supplied input
  passed via 'query' parameter to kvm.cgi and 'key' parameter to the avctalert.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"IBM GCM16 and GCM32 Global Console Manager switches with
  firmware versions before 1.20.20.23447.");

  script_tag(name:"solution", value:"Update to firmware version 1.20.20.23447 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34132");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68779");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68939");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jul/113");
  script_xref(name:"URL", value:"http://www.ibm.com/support/entry/portal/docdisplay?lndocid=migr-5095983");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:443);

res = http_get_cache(item:"/login.php", port:port);

if(">GCM" >< res) {

  url = "/avctalert.php?key=<script>alert(document.cookie)</script>";

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
