# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114043");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2018-11-05 18:50:00 +0100 (Mon, 05 Nov 2018)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_name("March Networks VisionWEB Default Credentials (HTTP)");
  script_dependencies("gb_march_networks_vision_web_detect.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8001);
  script_mandatory_keys("march_networks/visionweb/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://customvideosecurity.com/blog/tag/default-password-axis/");

  script_tag(name:"summary", value:"The remote installation of March Networks VisionWEB is using
  known default credentials.");

  script_tag(name:"vuldetect", value:"Checks if a successful login to March Networks VisionWEB is
  possible.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"insight", value:"The installation of March Networks VisionWEB is lacking a proper
  password configuration, which makes critical information and actions accessible for people with
  knowledge of the default credentials.");

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
include("http_keepalive.inc");

CPE = "cpe:/a:march_networks:visionweb";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

creds = make_array("admin", "");

url = "/setup/interface.js";

foreach cred(keys(creds)) {

  auth = "Basic " + base64(str: string(cred, ":", creds[cred]));

  req = http_get_req(port: port, url: url, add_headers: make_array("Accept-Encoding", "gzip, deflate",
                                                                   "Accept", "text/html, application/xhtml+xml, image/jxr, */*",
                                                                   "Pragma", "no-cache",
                                                                   "Authorization", auth));
  res = http_keepalive_send_recv(port: port, data: req);

  # nb: The second "function RequestFeatures()" is missing a compare operator. Please re-check this
  # when touching this detection (TODO task: VTD-2216).
  if("function FormFieldsToLoad(form, mode)" >< res && "function RequestFeatures()" &&
    "<p>Authentication Error: Access Denied, Missing authorization details.</p>" >!< res) {
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
