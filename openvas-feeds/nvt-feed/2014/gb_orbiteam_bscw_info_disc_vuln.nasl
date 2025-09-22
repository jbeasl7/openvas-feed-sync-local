# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804297");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-2301");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-16 11:22:00 +0530 (Fri, 16 May 2014)");
  script_name("OrbiTeam BSCW 'op' Parameter Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"OrbiTeam BSCW is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted HTTP GET request and check is it possible to read
  the filename of a document.");

  script_tag(name:"insight", value:"The flaw exists as the program associates filenames of documents with values
  mapped from the 'op' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information by enumerating the names of all objects stored in BSCW without prior authentication.");

  script_tag(name:"affected", value:"OrbiTeam BSCW before version 5.0.8");

  script_tag(name:"solution", value:"Upgrade to OrbiTeam BSCW version 5.0.8 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/May/37");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67284");
  script_xref(name:"URL", value:"https://xforce.iss.net/xforce/xfdb/93030");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126551");
  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2014-003");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

bscwPort = http_get_port(default:80);

rcvRes = http_get_cache(item:"/", port:bscwPort);

if(">BSCW administrator<" >!< rcvRes){
  exit(0);
}

req = http_get(item:"/pub/bscw.cgi/?op=inf", port:bscwPort);
rcvRes = http_keepalive_send_recv(port:bscwPort, data:req, bodyonly:TRUE);
if('"banner ruled_banner"' >< rcvRes)
{
  rcvRes = eregmatch(pattern:'The document can be found <A HREF="' +
           'http://.*(/pub/bscw.cgi/(.*)/?op=inf)">here', string:rcvRes);
  if(rcvRes[1]){
    url = rcvRes[1];
  }

  req = http_get(item:url, port:bscwPort);
  rcvRes = http_keepalive_send_recv(port:bscwPort, data:req, bodyonly:TRUE);
  if("server_logo_bscw.jpg" >< rcvRes)
  {
    rcvRes = eregmatch(pattern:'The document can be found <A HREF="' +
             'http://.*(/pub/bscw.cgi/(.*)/?op=inf)">here', string:rcvRes);
    if(rcvRes[1]){
      url = rcvRes[1];
    }

    req = http_get(item:url, port:bscwPort);
    rcvRes = http_send_recv(port:bscwPort, data:req, bodyonly:TRUE);

    if(rcvRes && rcvRes =~ '<td.*class="iValueB".*width=.*">(.*)</td>')
    {
      security_message(port:bscwPort);
      exit(0);
    }
  }
}

exit(99);
