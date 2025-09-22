# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801396");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2933");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AV Arcade 'ava_code' Cookie Parameter SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60799");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42023");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14494/");

  script_tag(name:"insight", value:"The flaws are due to an improper validation of authentication
  cookies in the 'index.php' script, when processing the 'ava_code' cookie parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"AV Arcade is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security
  restrictions and gain unauthorized administrative access to the vulnerable application.");

  script_tag(name:"affected", value:"AV Scripts AV Arcade version 3.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/avarcade", "/avarcade/upload" , http_cgi_dirs(port:port))){

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">AV Arcade" >< res && ">AV Scripts</" >< res){

    req = http_get(item: dir + "/admin/stats.php", port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(">AV Arcade" >< res){
      version = eregmatch(pattern:"> ([0-9.]+)", string:res);
      if(version[1]){
        if(version_is_equal(version:version[1], test_version:"3.0")){
          report = report_fixed_ver(installed_version:version[1], fixed_version:"WillNotFix");
          security_message(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}

exit(99);
