# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zkteco:zkbiosecurity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809335");
  script_version("2024-06-21T15:40:03+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 15:40:03 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-10-06 14:18:22 +0530 (Thu, 06 Oct 2016)");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("ZKTeco ZKBioSecurity Multiple Vulnerabilities (Jul 2016)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zkteco_zkbiosecurity_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8088);
  script_mandatory_keys("ZKTeco/ZKBioSecurity/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"ZKTeco ZKBioSecurity is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request and check whether it is able
  to read the password file or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - A use of hard-coded credentials.

  - An improper verification of requests.

  - An improper vareification of input passed to 'xmlPath' parameter.

  - The way visLogin.jsp script processes the login request via the
  'EnvironmentUtil.getClientIp(request)' method.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to bypass
  local authentication, to read arbitrary files, and also leads to further attacks.");

  script_tag(name:"affected", value:"ZKTeco ZKBioSecurity version 3.0.1.0_R_230 and probably
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40324");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40325");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40326");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40327");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/manager/";
host = http_host_name( port:port);

req =  'GET ' + url + ' HTTP/1.1\r\n' +
       'Host: ' + host + '\r\n' +
       'Connection: keep-alive\r\n' +
       'Authorization: Basic emt0ZWNvOnprdDEyMw==\r\n' +
       'Upgrade-Insecure-Requests: 1\r\n' +
       '\r\n';
res = http_keepalive_send_recv(port:port, data:req);

if(!ver = eregmatch( pattern:'Location: https?://' + host + '/manager/html;jsessionid=(.*CSRF_NONCE=[0-9A-Z]{32})', string:res)) {
  exit(0);
}

if(!ses = eregmatch( pattern:"Location: https?://" + host + '/manager/html;jsessionid=(.*)\\?', string:res)) {
  exit(0);
}

url2 = dir + "/manager/jmxproxy/?j2eeType=Servlet";

req2 = 'GET ' + url2 + ' HTTP/1.1\r\n' +
       'Host: ' + host + '\r\n' +
       'Cookie: JSESSIONID='+ses[1]+'\r\n' +
       'Authorization: Basic emt0ZWNvOnprdDEyMw==\r\n' +
       'Connection: keep-alive\r\n'+
       'Upgrade-Insecure-Requests: 1\r\n' +
       '\r\n';
resp = http_keepalive_send_recv(port:port, data:req2);

if("OK - Number of results:" >< resp && "Name: Catalina:" >< resp &&
   "modelerType:" >< resp && "minTime:" >< resp) {
  report = http_report_vuln_url(port:port, url:url2);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
