# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804223");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-01-10 13:11:49 +0530 (Fri, 10 Jan 2014)");
  script_name("TYPO3 Default Admin Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_typo3_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("typo3/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://wiki.typo3.org/TYPO3_Installation_Basics");

  script_tag(name:"summary", value:"TYPO3 is using default admin credentials.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP to the backend login with known
  default credentials.");

  script_tag(name:"insight", value:"TYPO3 installs with default admin credentials
  (admin/password).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access the
  program or system and gain privileged access.");

  script_tag(name:"affected", value:"All TYPO3 version which gets installed with default
  credentials.");

  script_tag(name:"solution", value:"After installation change all default installed accounts to use
  a unique and secure password. Please see the references for more information.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

host = http_host_name(port:port);

url = dir + "/typo3/index.php";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req, bodyonly:FALSE);

username = "admin";
password = "password";

challenge = eregmatch(pattern:'name="challenge" value="([a-z0-9]+)"', string:res);
if(!challenge)
  exit(0);

password = hexstr(MD5(password));
userident = hexstr(MD5(username + ":" + password + ":" + challenge[1]));
payload = "login_status=login&username=" + username + "&p_field=&commandLI=Log+In&" +
          "userident=" + userident + "&challenge=" + challenge[1] + "&redirect_url=" +
          "alt_main.php&loginRefresh=&interface=backend";

tcookie = eregmatch(pattern:"(be_typo_user=[a-z0-9]+\;)", string:res);
PHPSESSID = eregmatch(pattern:"(PHPSESSID=[a-z0-9]+\;?)", string:res);

if(!PHPSESSID[1])
  PHPSESSID[1] = "PHPSESSID=37dh7b4vkprsui40hmg3hf4716";

if(!tcookie[1] || !PHPSESSID[1])
  exit(0);

cCookie = tcookie[1] + ' showRefMsg=false; ' + PHPSESSID[1] + " typo3-login-cookiecheck=true";

useragent = http_get_user_agent();
req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Referer: http://", host, dir, "/typo3/alt_menu.php\r\n",
             "Connection: keep-alive\r\n",
             "Cookie: ", cCookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(payload), "\r\n\r\n",
             payload);
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

page = egrep(pattern:"^[Ll]ocation\s*:.*(backend|alt_main)\.php", string:res, icase:FALSE);
if(page) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
