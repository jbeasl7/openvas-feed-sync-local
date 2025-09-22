# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sierra_wireless:acemanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106077");
  script_version("2024-01-17T06:33:34+0000");
  script_tag(name:"last_modification", value:"2024-01-17 06:33:34 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-05-17 11:21:09 +0700 (Tue, 17 May 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Sierra Wireless AceManager Default Password (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_sierrawireless_acemanager_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("sierra_wireless/acemanager/http/detected");
  script_require_ports("Services/www", 9443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Sierra Wireless AceManager is using known default credentials
  for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to log in with the default users 'user' and 'viewer'.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

users = make_list("user", "viewer");

url = "/xml/Connect.xml";

headers = make_array("Content-Type", "text/xml",
                     "X-Requested-With", "XMLHttpRequest");

foreach user (users) {
  data = '<request xmlns="urn:acemanager">\r\n' +
         '<connect>\r\n' +
         '<login>' + user + '</login>\r\n' +
         '<password><![CDATA[12345]]></password>\r\n' +
         '</connect>\r\n' +
         '</request>';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("status='0' message='OK'" >< res)
    found_users += user + '\n';
}

if (found_users) {
  report = "It was possible to log in with the following users and the default password '12345'";
  report += '\n\n' + chomp(found_users);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
