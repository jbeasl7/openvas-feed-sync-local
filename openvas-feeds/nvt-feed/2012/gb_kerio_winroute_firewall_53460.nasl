# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103487");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2012-05-11 13:52:12 +0200 (Fri, 11 May 2012)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kerio WinRoute Firewall < 6.0.0 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Kerio_WinRoute/banner");

  script_tag(name:"summary", value:"Kerio WinRoute Firewall is prone to a remote source code
  disclosure vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view the source
  code of files in the context of the server process, this may aid in further attacks.");

  script_tag(name:"affected", value:"Kerio WinRoute Firewall prior to version 6.0.0.");

  script_tag(name:"solution", value:"Update to version 6.0.0 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53460");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);

if (banner !~ "Server\s*:\s*Kerio WinRoute Firewall")
  exit(0);

url = "/nonauth/login.php%00.txt";

if (http_vuln_check(port: port, url: url, pattern: "require_once",
                    extra_check: make_list("configNonauth", "CORE_PATH"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
