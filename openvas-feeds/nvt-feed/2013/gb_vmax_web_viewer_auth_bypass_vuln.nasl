# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803198");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-14 16:41:18 +0530 (Tue, 14 May 2013)");
  script_name("VMAX Web Viewer Default Credentials (HTTP)");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/05/12/sunday-shodan-defaults/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Boa/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"insight", value:"By default, Digital Watchdog VMAX Viewer installs with default
  user credentials (username/password combination). The 'admin' account has no
  password, which is publicly known and documented. This allows remote attackers
  to trivially access the program or system and gain privileged access.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"VMAX Web Viewer is using known default credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain administrative
  access, circumventing existing authentication mechanisms.");

  script_tag(name:"affected", value:"Digital Watchdog VMAX Viewer");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if("Server: Boa/" >!< banner){
  exit(0);
}

host = http_host_name(port:port);

url = '/cgi-bin/design/html_template/Login.cgi';

postData = "login_txt_id=admin&login_txt_pw=";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "^HTTP/1\.[01] 200" && 'location = "webviewer.cgi' >< res)
{
  security_message(port:port);
  exit(0);
}

exit(99);
