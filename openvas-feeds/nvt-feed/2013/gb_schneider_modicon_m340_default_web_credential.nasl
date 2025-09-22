# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:schneider-electric:modicon_m340";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103857");
  script_version("2024-09-17T05:05:45+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-09-17 05:05:45 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"creation_date", value:"2013-12-16 11:44:04 +0200 (Mon, 16 Dec 2013)");
  script_name("Schneider Modicon M340 Device Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_schneider_modicon_m340_detect.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("schneider_modicon/m340/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/12/08/schneider-modicon-m340-for-ethernet-multiple-default-credentials/");

  script_tag(name:"summary", value:"The remote Schneider Modicon M340 device is using known default
  credentials.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using default credentials.");

  script_tag(name:"insight", value:"It was possible to login as user 'USER' with password 'USER'.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/secure/embedded/http_passwd_config.htm?Language=English";

req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(!buf || buf !~ "^HTTP/1\.[01] 401" || buf !~ "WWW-Authenticate\s*:")
  exit(0);

auth = base64(str:"USER:USER");

req = ereg_replace(string:req, pattern:'\r\n\r\n', replace:'\r\nAuthorization: Basic ' + auth + '\r\n\r\n\r\n');
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf =~ "^HTTP/1\.[01] 200" && '<title>Passwords modification' >< buf) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
