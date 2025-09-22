# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171698");
  script_version("2025-08-22T15:40:55+0000");
  script_tag(name:"last_modification", value:"2025-08-22 15:40:55 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-22 12:28:50 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("FXC Router Devices Default Credentials (HTTP)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_fxc_router_http_detect.nasl",
                      "gb_default_credentials_options.nasl");
  script_mandatory_keys("fxc/router/http/detected");
  script_require_ports("Services/www", 443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote FXC router device is using known default
  credentials for the HTTP login.");

  script_tag(name:"vuldetect", value:"Checks if it is possible to login via HTTP with known
  default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"Edimax PS-1206MF printserver devices are known to be affected.
  Other devices or vendors might be affected as well.");

  script_tag(name:"solution", value:"Login to the device and change the password of the affected
  account.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

url = "/";

res = http_get_cache(port: port, item: url);

username = "admin";
password = "admin";

if ("/cgi-bin/login.apply" >< res) {
  url = "/cgi-bin/login.apply";
  data_str = isotime_now();
  data_str = substr(data_str, 0, 7) + substr(data_str, 9, 12);
  post_data = "username_input="+ username + "&password_input=" + password + "&lang=en_EN&hashstr=" +
              data_str + "&username=" + username + "&password=" + password;
  unix_time = "" + unixtime();
  cookie_no = substr(unix_time, strlen(unix_time) - 6, strlen(unix_time) - 1);

  cookie = "cookieno=" + cookie_no + "; username=" + username +"; password=" + password;

  headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                       "Cookie", cookie);

  req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res && res =~ "^HTTP/1\.[01] (200|30.)" && "window.open('/home.htm'" >< res)
    report += '\nUsername: "' + username + '", Password: "' + password + '"\n';
} else {
  url = "/cgi/login.cgi";

  headers = make_array("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8",
                       "X-Requested-With", "XMLHttpRequest");

  post_data = "username=" + username + "&password=" + password;

  req = http_post_put_req(port: port, url: url, data: post_data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if (res && res =~ "^HTTP/1\.[01] (200|30.)" && "login error" >!< res)
    report += '\nUsername: "' + username + '", Password: "' + password + '"\n';
}

if (report) {
  report = 'It was possible to login with the following credentials:\n' + chomp(report);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
