# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900204");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3726");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_name("MicroWorld MailScan for Mail Servers < 6.4a Multiple Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445, 10443);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31534");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30700");
  script_xref(name:"URL", value:"http://www.oliverkarow.de/research/mailscan.txt");

  script_tag(name:"summary", value:"MailScan is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - an input validation error within the web administration interface.

  - the web administration interface does not properly restrict access
  to certain pages. can cause an authentication-bypass vulnerability.

  - an input passed via URL to the web administration interface is not
  properly sanitized before being returned to the user.");

  script_tag(name:"affected", value:"MicroWorld MailScan for Mail Servers 5.6a and prior versions.");

  script_tag(name:"solution", value:"Upgrade to MicroWorld MailScan Version 6.4a or later.");

  script_tag(name:"impact", value:"Successful Remote exploitation will allow, to gain unauthorized
  access to disclose sensitive information, directory traversal attacks,
  cross site scripting, execution of arbitrary script code within the
  context of the website to steal cookie-based authentication credentials.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("smb_nt.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = 10443;
if( ! get_port_state( port ) ) exit( 0 );

req = http_get(item:"/main.dll", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if("Welcome to MicroWorld's MailScan" >!< res)
  exit(0);

if(!safe_checks()) {
  url = "/../../../../boot.ini";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "[boot loader]" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

mailScanVer = registry_get_sz(key:"SOFTWARE\MicroWorld\C:#PROGRA~1#MAILSCAN" +
                              "#MAILSCAN.INI\General", item:"Version");
if(!mailScanVer)
  exit(0);

if(egrep(pattern:"^([0-4]\..*|5\.[0-5][a-z]?|5\.6a?)$", string:mailScanVer)){
  security_message(port:port);
  exit(0);
}

exit(99);
