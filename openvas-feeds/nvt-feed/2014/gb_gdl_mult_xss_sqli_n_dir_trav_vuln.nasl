# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804509");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-03-05 14:58:48 +0530 (Wed, 05 Mar 2014)");
  script_name("Ganesha Digital Library Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Ganesha Digital Library is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitation of user supplied input via
  'newlang' and 'newtheme' parameters to index.php and gdl.php, 'id' parameter
  to download.php and 'keyword' parameter to gdl.php scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code, manipulate SQL commands in backend database and read arbitrary
  files.");

  script_tag(name:"affected", value:"Ganesha Digital Library version 4.2, Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31961");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65874");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125464");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/gdl", "/diglib", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  gdlRes = http_get_cache(item:string(dir, "/"),  port:http_port);

  if("ITB. All rights reserved" >< gdlRes || "Powered By GDL" >< gdlRes)
  {
    ## Crafted Url
    url = dir + "/gdl.php?mod=search&action=folks&keyword=''%22%3E%3Cscript" +
                 "%3Ealert(document.cookie)%3C/script%3E&type=all&submit=OK";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document\.cookie\)</script>",
       extra_check: "GDL"))
    {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
