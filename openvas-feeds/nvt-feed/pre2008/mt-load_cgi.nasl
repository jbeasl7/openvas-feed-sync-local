# SPDX-FileCopyrightText: 2004 Rich Walchuck
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sixapart:movable_type";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16169");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Movable Type Initialization Script Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2004 Rich Walchuck");
  script_family("Web application abuses");
  script_dependencies("gb_movable_type_http_detect.nasl");
  script_mandatory_keys("sixapart/movabletype/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"mt-load.cgi is installed by the Movable Type Publishing
  Platform.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Failure to remove mt-load.cgi could enable someone else to
  create a weblog in your Movable Type installation, and possibly gain access to your data.");

  script_tag(name:"solution", value:"Remove the mt-load.cgi script after installation.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("list_array_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/mt/mt-load.cgi";

if (http_is_cgi_installed_ka(port: port, item: url)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
