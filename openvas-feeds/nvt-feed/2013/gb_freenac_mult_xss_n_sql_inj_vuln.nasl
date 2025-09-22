# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803707");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-6559", "CVE-2012-6560");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-05-24 13:19:39 +0530 (Fri, 24 May 2013)");
  script_name("FreeNAC Multiple XSS and SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53617");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75761");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18900");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL commands or execute arbitrary HTML or web script in a user's
  browser session in context of an affected site.");

  script_tag(name:"affected", value:"FreeNAC version 3.02 and prior");

  script_tag(name:"insight", value:"The application does not validate the 'comment', 'mac',
  'graphtype', 'type', and 'name' parameters upon submission to the stats.php
  and 'comment' parameter upon submission to the deviceadd.php script.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"FreeNAC is prone to multiple cross site scripting, HTML injection and SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/freenac", "/nac", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  rcvRes = http_get_cache(item:string(dir, "/login.php"), port:port);

  if(rcvRes && ">FreeNAC website<" >< rcvRes && ">FreeNAC ::" >< rcvRes)
  {
    url = dir + "/stats.php?graphtype=bar&type=vlan13<script>alert" +
                "(document.cookie)</script>";

    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document\.cookie\)</script>",
       extra_check: make_list(">Server status<", ">Device Class")))
    {
      report = http_report_vuln_url( port:port, url:url );
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
