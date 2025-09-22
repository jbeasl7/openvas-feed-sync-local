# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114064");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-02-05 14:02:40 +0100 (Tue, 05 Feb 2019)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Default Accounts");
  script_name("Avtech IP Camera Default Credentials (HTTP)");
  script_dependencies("gb_avtech_device_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("avtech/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://www.surveillance-download.com/user/network_setting.pdf");

  script_tag(name:"summary", value:"The remote installation of Avtech's IP camera software is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Avtech's IP camera software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to the IP camera software is possible.");

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

CPE = "cpe:/o:avtech:avtech_device_firmware";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

creds = make_array("admin", "admin");

foreach cred(keys(creds)) {

  #/cgi-bin/nobody/VerifyCode.cgi?account=YWRtaW46YWRtaW4=
  url = "/cgi-bin/nobody/VerifyCode.cgi?account=" + base64(str: cred + ":" + creds[cred]);

  req = http_get_req(port: port, url: url);

  res = http_send_recv(port: port, data: req);

  if(res =~ "Set-Cookie: SSID=[A-Za-z0-9=]+;") {
    VULN = TRUE;
    report += '\nusername: "' + cred + '", password: "' + creds[cred] + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
