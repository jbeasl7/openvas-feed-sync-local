# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:loxone:miniserver_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805298");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-03-10 09:36:22 +0530 (Tue, 10 Mar 2015)");

  script_name("Loxone Smart Home Multiple Vulnerabilities (Mar 2015)");

  script_tag(name:"summary", value:"Loxone Smart Home is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - the device transmitting all data in cleartext.

  - HTTP requests do not require multiple steps, explicit confirmation, or a
  unique token when performing certain sensitive actions.

  - the '/dev/cfg/version' script does not validate input appended to the
  response header before returning it to the user.

  - the '/dev/sps/io/' script does not validate input passed via the URL before
  returning it to users.

  - the '/dev/sps/addcmd/' script does not validate input to the description field
  in a new task before returning it to users.

  - the program storing user credentials in an insecure manner.

  - improper restriction of JavaScript from one web page from accessing another
  when the pages originate from different domains.

  - an unspecified error related to malformed HTTP requests or using the
  synflood metasploit module.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to:

  - conduct a man-in-the-middle attack.

  - conduct a cross-site request forgery attack.

  - conduct a cross-frame scripting (XFS) attack.

  - conduct a denial-of-service (DoS) attack.

  - decrypt user credentials.

  - insert additional arbitrary HTTP headers.

  - execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Loxone Smart Home version 5.49 and probably prior.");

  script_tag(name:"solution", value:"Upgrade to Loxone Smart Home version 6.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130577");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_loxone_miniserver_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("loxone/miniserver/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/dev/cfg/version%0D%0A%0D%0A<html><script>alert(document.cookie)</script></html>";
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document\.cookie\)</script>",
   extra_check:">Loxone Miniserver error<")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
