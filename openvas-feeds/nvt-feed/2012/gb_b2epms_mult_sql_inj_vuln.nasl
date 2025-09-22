# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802861");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-06-01 13:07:29 +0530 (Fri, 01 Jun 2012)");
  script_name("b2ePMS Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53690");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75923");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18935");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113064/b2epms10-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause SQL injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"b2ePMS version 1.0");

  script_tag(name:"insight", value:"Multiple flaws are due to input passed via phone_number,
  msg_caller, phone_msg, msg_options, msg_recipients and signed parameters to
  'index.php' is not properly sanitised before being used in SQL queries, which
  allows attackers to execute arbitrary SQL commands in the context of an
  affected application or site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"b2ePMS is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
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

foreach dir (make_list_unique("/", "/b2epms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && "<title>b2ePMS" >< res && "New Phone Message" >< res ) {

    postdata = "phone_number='&phone_msg=SQL-TEST&msg_options=Please+call&" +
               "msg_recipients%5B%5D=abc%40gmail.com&signed=LOC&Submit=Send";

    req = string("POST ", dir, "/post_msg.php HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Referer: http://", host, dir, "/index.php\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n\r\n",
                  postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res && ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
      ('You have an error in your SQL syntax;' >< res))
    {
      security_message(port);
      exit(0);
    }
  }
}

exit(99);
