# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:quest:dr_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813012");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-03-09 13:07:37 +0530 (Fri, 09 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Quest DR Series Appliance Default Credentials (HTTP)");

  script_tag(name:"summary", value:"Quest DR Series Appliances are using known default credentials
  for the HTTP login.");

  script_tag(name:"vuldetect", value:"Send crafted data via 'HTTP POST' request
  and check whether it is able to login or not.");

  script_tag(name:"insight", value:"The flaw exists because Quest DR Series
  Appliance has default credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to access the Web GUI and login directly into the DR system.");

  script_tag(name:"affected", value:"Quest DR Series Appliance.");

  script_tag(name:"solution", value:"Change the default credentials.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_xref(name:"URL", value:"https://support.quest.com/dr-series/kb/220574/what-are-the-default-login-credentials-for-the-dr-");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_dependencies("gb_quest_dr_series_appliance_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("quest/dr/appliance/detected");
  script_require_ports("Services/www", 443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/ws/v1.0/jsonrpc";
login_data = '{"jsonrpc":"2.0","method":"Logon","params":{"UserName":"administrator","Password":"St0r@ge!"},"id":1}';

req = http_post_put_req(port:port, url:url, data:login_data,
                        add_headers:make_array("Content-Type", "text/plain"));
buf = http_keepalive_send_recv(port:port, data:req);

if(buf =~ "^HTTP/1\.[01] 200" && '"Error: Login username or password incorrect' >!< buf &&
   '"SessionCookie' >< buf && '"userRole' >< buf && '"ServiceID' >< buf)
{
  report = 'It was possible to logging directly into the DR system with the following credentials:\n\nUsername: administrator\nPassword: St0r@ge!';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
