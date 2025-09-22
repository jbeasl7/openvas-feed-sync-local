# SPDX-FileCopyrightText: 2004 Sverre H. Huseby
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:horde_groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11617");
  script_version("2025-03-27T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-03-27 05:38:50 +0000 (Thu, 27 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Horde Information Disclosure Vulnerability (Nov 2005) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2004 Sverre H. Huseby");
  script_family("Web application abuses");
  script_dependencies("horde_http_detect.nasl");
  script_mandatory_keys("horde/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Horde is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"Some test scripts may leak server-side information that may be
  valuable to an attacker.");

  script_tag(name:"solution", value:"test.php and imp/test.php should be deleted, or they should be
  made unreadable by the web server.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = make_list("/test.php",
                  "/test.php3",
                  "/imp/test.php",
                  "/imp/test.php3");

foreach file (files) {
  url = dir + file;

  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("PHP Version" >< res && ("Horde Version" >< res || "IMP Version" >< res)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
