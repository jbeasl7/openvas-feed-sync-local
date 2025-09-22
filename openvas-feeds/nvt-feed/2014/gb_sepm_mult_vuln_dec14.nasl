# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805203");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2014-3439", "CVE-2014-3438", "CVE-2014-3437");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-12-04 09:43:28 +0530 (Thu, 04 Dec 2014)");
  script_name("Symantec Endpoint Protection Manager Multiple Vulnerabilities (Dec 2014)");

  script_tag(name:"summary", value:"Symantec Endpoint Protection Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The /console/Highlander_docs/SSO-Error.jsp script does not validate
    input to the 'ErrorMsg' parameter before returning it to users.

  - ConsoleServlet does not properly sanitize user input supplied via the
    'ActionType' parameter.

  - Incorrectly configured XML parser accepting XML external entities from an
    untrusted source.

  - The /portal/Loading.jsp script does not validate input to the 'uri' parameter
    before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to arbitrary files, write to or overwrite arbitrary files and
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection Manager (SEPM)
  12.1 before RU5.");

  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection Manager
  12.1 RU5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031176");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70845");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);

}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

http_port = http_get_port(default:8443);

res = http_get_cache(item:"/", port:http_port);

if(res && ">Symantec Endpoint Protection Manager<" >< res
       && res =~ "&copy.*Symantec Coorporation<")
{

  url = "/console/Highlander_docs/SSO-Error.jsp?ErrorMsg=<script>alert(document"
        + ".cookie)</script>";

  req = http_get(item:url, port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< res
         && ">SSO Error<" >< res)
  {
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);
