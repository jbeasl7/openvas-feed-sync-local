# SPDX-FileCopyrightText: 2001 INTRANODE
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:omnicron:omnihttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10716");
  script_version("2025-04-11T15:45:04+0000");
  script_cve_id("CVE-2001-0778");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("OmniPro HTTPd <= 2.08 Scripts Source Full Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 INTRANODE");
  script_family("Web Servers");
  script_dependencies("gb_omnihttpd_detect.nasl");
  script_mandatory_keys("omnihttpd/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2788");

  script_tag(name:"summary", value:"OmniPro HTTPd suffers from a security vulnerability that permits
  malicious users to get the full source code of scripting files.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"By appending an ASCII/Unicode space char '%20' at the script
  suffix, the web server will no longer interpret it and rather send it back clearly as a simple
  document to the user in the same manner as it usually does to process HTML-like files.

  The flaw does not work with files located in CGI directories (e.g cgibin, cgi-win)

  Exploit: GET /test.php%20 HTTP/1.0");

  script_tag(name:"affected", value:"OmniPro HTTPd version 2.08 and prior is known to be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

function check(poison, port) {

  local_var poison, port;
  local_var soc, req, res, regex_signature;

  # nb: Should be always before the first http_open_socket() call
  req = http_get(item:poison, port:port);

  soc = http_open_socket(port);
  if(!soc)
    return(0);

  send(socket:soc, data:req);
  res = http_recv(socket:soc);
  http_close_socket(soc);

  regex_signature[2] = "<?";
  if(regex_signature[2] >< res)
    return(1);
  else
    return(0);
}

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

Egg = "%20 ";
signature = "test.php";

poison = string("/", signature, Egg);

if(check(poison:poison, port:port)) {
  report = http_report_vuln_url(port:port, url:poison);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
