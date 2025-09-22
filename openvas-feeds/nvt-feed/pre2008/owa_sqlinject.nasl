# SPDX-FileCopyrightText: 2005 Michael J. Richardson
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17636");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2005-0420");
  script_name("Outlook Web Access URL Injection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michael J. Richardson");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/36079/Exploit-Labs-Security-Advisory-2005.1.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12459");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Due to a lack of sanitization of the user input, the remote version of Microsoft
  Outlook Web Access 2003 is vulnerable to URL injection which can be exploited to redirect a user to a different,
  unauthorized web server after authenticating to OWA.");

  script_tag(name:"impact", value:"This unauthorized site could be used to capture sensitive information by
  appearing to be part of the web application.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

url = "/exchweb/bin/auth/owalogon.asp?url=http://12345678910";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if(ereg(pattern:"^HTTP/1\.[01] 200 ", string:res) &&
   "owaauth.dll" >< res &&
   '<INPUT type="hidden" name="destination" value="http://12345678910">' >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
