# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806053");
  script_version("2021-09-22T15:39:37+0000");
  script_cve_id("CVE-2015-7765", "CVE-2015-7766");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-22 15:39:37 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"creation_date", value:"2015-09-16 11:10:46 +0530 (Wed, 16 Sep 2015)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("ManageEngine OpManager <= 11.6 Multiple Vulnerabilities - Active Check");

  script_tag(name:"summary", value:"ManageEngine OpManager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"It was possible to login with default credentials:
  IntegrationUser/plugin.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  SQL queries on the backend PostgreSQL instance with administrator rights and access shell with
  SYSTEM privileges.");

  script_tag(name:"affected", value:"ManageEngine OpManager versions 11.6 and earlier.");

  script_tag(name:"solution", value:"Install the patch from the referenced vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38174");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133596");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Sep/66");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/pgsql-submitquery-do-vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8060);
  script_mandatory_keys("manageengine/opmanager/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(port:port, cpe:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/jsp/Login.do";
useragent = http_get_user_agent();
postData = 'clienttype=html&isCookieADAuth=&domainName=NULL&authType=localUser'+
           'Login&webstart=&ScreenWidth=1295&ScreenHeight=637&loginFromCookie'+
           'Data=&userName=IntegrationUser&password=plugin&uname=';

len = strlen(postData);

host = http_host_name(port:port);

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      postData;
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(res =~ "^HTTP/1\.[01] 302" && "index.jsp" >< res) {

  cookie = eregmatch(pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:res);
  if(!cookie[1])
    exit(0);

  req = string("GET ", dir, "/apiclient/ember/index.jsp HTTP/1.1\r\n",
               "Host:", host, "\r\n",
               "Connection: Close\r\n",
               "Cookie: flashversionInstalled=11.2.202; JSESSIONID=", cookie[1], "\r\n\r\n");
  res = http_send_recv(port:port, data:req, bodyonly:FALSE);
  if("OpManager" >< res && 'HomeDashboard' >< res && 'Logout.do' >< res) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);