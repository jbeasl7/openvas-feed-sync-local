# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114051");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-12-25 15:49:51 +0100 (Tue, 25 Dec 2018)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_name("Arecont Vision NVR Default Credentials (HTTP)");
  script_dependencies("gb_arecont_vision_nvr_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("arecont_vision/nvr/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://arecontvision.com/marketing/contents/AV_ConteraCMR_QSG.pdf");

  script_tag(name:"summary", value:"The remote installation of Arecont Vision's NVR software is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of Arecont Vision's NVR software is lacking a proper
  password configuration, which makes critical information and actions accessible for people with knowledge
  of the default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to the NVR is possible.");

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

CPE = "cpe:/h:arecont_vision:nvr";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

#Because we can't use multiple keys, the first part(key) is the password and the second part(value) is the username.
creds = make_array("admin", "admin",
                  "1234", "admin",
                  "", "");

foreach cred(keys(creds)) {

  #To avoid confusion with previous scripts, because of the reversed order:
  username = creds[cred];
  password = cred;

  url = "/auth.cgi";

  #Authorization: Basic YWRtaW46YWRtaW4=
  auth = "Basic " + base64(str: username + ":" + password);

  data = ""; #No data field required

  req = http_post_put_req(port: port, url: url, data: data, add_headers: make_array("Content-Length",  "0",
                                                                                "Authorization", auth));

  res = http_send_recv(port: port, data: req);

  if("Content-Length: 2" >< res && "OK" >< res) {
    VULN = TRUE;
    report += '\nusername: "' + username + '", password: "' + password + '"';
  }
}

if(VULN) {
  report = "It was possible to login with the following default credentials: " + report;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
