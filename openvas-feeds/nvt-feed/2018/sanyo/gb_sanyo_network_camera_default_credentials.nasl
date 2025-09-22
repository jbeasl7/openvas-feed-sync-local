# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.114021");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-15 14:08:31 +0200 (Wed, 15 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Sanyo Network Camera Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_sanyo_network_camera_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sanyo/network_camera/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Sanyo network cameras use the default credentials admin:admin.");

  script_tag(name:"vuldetect", value:"Tries to login using default credentials.");

  script_tag(name:"affected", value:"All Sanyo cameras using this web interface.");

  script_tag(name:"solution", value:"Change the default password.");

  script_xref(name:"URL", value:"https://ipvm.com/reports/ip-cameras-default-passwords-directory");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

CPE = "cpe:/h:sanyo:network_camera";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

username = "admin";
password = "admin";

auth_header = make_array("Authorization", "Basic " + base64(str: username + ":" + password));
req = http_get_req(port: port, url: "/", add_headers: auth_header);
res = http_keepalive_send_recv(port: port, data: req);

if(('<IMG src="../img/SANYO_lan.gif"></TD>' >< res && "<TITLE>SANYO  NETWORK CAMERA</TITLE>" >< res)
    || 'top.window.location.replace("/cgi-bin/lang.cgi");' >< res) {
  report = 'It was possible to login using the username "' + username + '" and the password "' + password + '".';

  #Version detection with authorization
  session = eregmatch(pattern: "NOBSESS=([0-9a-zA-z]+)", string: res);

  sessionCookie = session[0];
  versionUrl = "/cgi-bin/option.cgi";

  #Some versions do not expect or send you a session cookie
  if(sessionCookie) {
    req = http_get_req(port: port,
                       url: versionUrl,
                       add_headers: make_array("Authorization", "Basic " + base64(str: username + ":" + password) + "=",
                                               "Cookie", sessionCookie));
  }
  else {
    req = http_get_req(port: port,
                       url: versionUrl,
                       add_headers: make_array("Authorization", "Basic " + base64(str: username + ":" + password) + "="));
  }

  res = http_keepalive_send_recv(port: port, data: req);

  #MAIN Ver. 2.03-02 || CAM MAIN Ver. 2.03-06
  #SUB Ver. 1.01-00  || CAM SUB Ver. 1.01-00
  mainVer = eregmatch(pattern: "(CAM)?\s*MAIN\s*Ver.\s*([0-9.-]+)", string: res);
  subVer = eregmatch(pattern: "(CAM)?\s*SUB\s*Ver.\s*([0-9.-]+)", string: res);

  if(mainVer[2]) set_kb_item(name: "sanyo/network_camera/main/version", value: mainVer[2]);
  if(subVer[2])  set_kb_item(name: "sanyo/network_camera/sub/version", value: subVer[2]);

  security_message(data: report, port: port);
  exit(0);
}

exit(99);
