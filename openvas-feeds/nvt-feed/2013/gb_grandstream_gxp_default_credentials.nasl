# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:grandstream:gxp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103861");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-19 11:42:04 +0200 (Thu, 19 Dec 2013)");
  script_name("Grandstream GXP VOIP Phones Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_grandstream_gxp_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("grandstream/gxp/http/port");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/10/30/grandstream-gxp-voip-phones-default-credentials/");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote Grandstream GXP VOIP Phone is using known default credentials.");

  script_tag(name:"insight", value:"This issue may be exploited by a remote attacker to
  gain access to sensitive information or modify system configuration.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/login.htm";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

gnkey = eregmatch(pattern:'<input name="gnkey" type=hidden value=([^>]+)>', string:buf);
if(isnull(gnkey[1]))
  exit(0);

gnkey = gnkey[1];

credentials = make_list("123", "admin");

url = "/dologin.htm";

foreach c(credentials) {

  login_data = 'P2=' + c + '&Login=Login&gnkey=' + gnkey;

  req = http_post(item:url, port:port, data:login_data);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("End User Password:" >< buf && "PPPoE account ID:" >< buf && "PPoE password:" >< buf) {
    report = 'It was possible to login into the remote Grandstream device using the password "' + c + '".\n';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
