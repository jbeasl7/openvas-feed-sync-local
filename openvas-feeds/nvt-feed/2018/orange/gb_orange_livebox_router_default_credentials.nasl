# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114054");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-27 17:18:05 +0100 (Thu, 27 Dec 2018)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_name("Orange Livebox Router Default Credentials (HTTP)");
  script_dependencies("gb_orange_livebox_router_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("orange/livebox/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://github.com/zadewg/LIVEBOX-0DAY");
  script_xref(name:"URL", value:"http://setuprouter.com/router/arcadyan/arv7519/login.htm");

  script_tag(name:"summary", value:"The remote installation of Orange Livebox is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Orange Livebox is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to the router is possible.");

  script_tag(name:"solution", value:"Change the passwords for user and admin access.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");

CPE = "cpe:/h:orange:livebox";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

creds = make_array("admin", "admin",
                   "kpn", "kpn-adsl");

foreach cred(keys(creds)) {

  url = "/cgi-bin/login.exe";

  #user=admin&pws=admin
  data = "user=" + cred + "&pws=" + creds[cred];

  req = http_post_put_req(port: port, url: url, data: data, add_headers: make_array("Cache-Control",  "max-age=0"));

  res = http_send_recv(port: port, data: req);

  sessID = eregmatch(pattern: "Set-Cookie: (aDuPtHh_OSPPH1=[a-zA-Z0-9_#]+);", string: res, icase: TRUE);
  if(isnull(sessID[1])) exit(99); #Login unsuccessful
  else {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';

    #Now we need to log out, or else the host is locked up forever until a restart or until the session expires, if it ever does.
    req = http_get_req(port: port, url: "/cgi-bin/logout.exe", add_headers: make_array("Cookie", sessID[1]));

    res = http_send_recv(port: port, data: req);
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
