# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:smartertools:smartermail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902432");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)");
  script_cve_id("CVE-2011-2148", "CVE-2011-2149", "CVE-2011-2150", "CVE-2011-2151",
                "CVE-2011-2152", "CVE-2011-2153", "CVE-2011-2154", "CVE-2011-2155",
                "CVE-2011-2156", "CVE-2011-2157", "CVE-2011-2158", "CVE-2011-2159");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SmarterMail Multiple Vulnerabilities (May 2011)");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/240150");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/MORO-8GYQR4");
  script_xref(name:"URL", value:"http://xss.cx/examples/smarterstats-60-oscommandinjection-directorytraversal-xml-sqlinjection.html.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 9998);
  script_mandatory_keys("smartermail/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"SmarterMail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are present in the application. More detail is
  available from the referenced advisory.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct
  cross-site scripting (XSS), command execution and directory traversal attacks.");

  script_tag(name:"affected", value:"SmarterTools SmarterMail versions 6.0 and prior.");

  script_tag(name:"solution", value:"Upgrade to SmarterTools SmarterMail 8.0 or later.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/Login.aspx?shortcutLink=autologin&txtSiteID=admin&txtUser=admin&txtPass=admin";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if("txtUser=admin&" >< res && "txtPass=admin" >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
