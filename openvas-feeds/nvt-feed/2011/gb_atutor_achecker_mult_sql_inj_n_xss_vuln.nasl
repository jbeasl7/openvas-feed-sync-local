# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801982");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Atutor AChecker Multiple SQL Injection and XSS Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17630/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49093");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103763/ZSL-2011-5035.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103762/ZSL-2011-5034.txt");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Atutor AChecker 1.2 (build r530).");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - input passed via the parameter 'myown_patch_id' in '/updater/patch_edit.php'
  and the parameter 'id' in '/user/user_create_edit.php' script is not
  properly sanitised before being used in SQL queries.

  - input through the GET parameters 'id', 'p' and 'myown_patch_id' in
  multiple scripts is not sanitized allowing the attacker to execute HTML
  code or disclose the full path of application's residence.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Atutor AChecker is prone to multiple cross site scripting and SQL injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

foreach dir (make_list("/AChecker", "/")) {

  if( dir == "/" ) dir = "";
  url = dir + "/checker/index.php";
  res = http_get_cache(item:url, port:port);

  if(res && "Web Accessibility Checker<" >< res && '>Check Accessibility' >< res) {

    url = dir + '/documentation/frame_header.php?p="><script>alert(document.cookie)</script>';
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '"><script>alert(document.cookie)</script>' >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }

    url = dir + "/user/user_create_edit.php?id='1111";
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if('You have an error in your SQL syntax;' >< res){
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
