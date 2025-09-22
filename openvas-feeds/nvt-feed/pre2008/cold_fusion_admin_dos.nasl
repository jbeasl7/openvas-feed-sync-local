# SPDX-FileCopyrightText: 2000 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10581");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1314");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0538");
  script_name("Cold Fusion Administration Page Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Use HTTP basic authentication to restrict access to this page or
  remove it entirely if remote administration is not a requirement.

  A patch should be available from the vendor.");

  script_tag(name:"summary", value:"A denial of service vulnerability exists within the Allaire
  ColdFusion web application server (version 4.5.1 and earlier) which allows an
  attacker to overwhelm the web server and deny legitimate web page requests.");

  script_tag(name:"impact", value:"By downloading and altering the login HTML form an attacker can
  send overly large passwords (> 40.0000 chars) to the server, causing it to stop responding.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

# nb: CFIDE will work with CF Linux also
url = "/CFIDE/administrator/index.cfm";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("PasswordProvided" >< res && "cf50" >!< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
