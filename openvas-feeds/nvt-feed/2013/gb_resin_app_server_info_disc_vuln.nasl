# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:caucho:resin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803713");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-06-10 16:11:12 +0530 (Mon, 10 Jun 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Caucho Resin <= 4.0.36 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_caucho_resin_http_detect.nasl");
  script_mandatory_keys("caucho/resin/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Caucho Resin is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an improper sensitization of the 'file'
  parameter when used for reading help files. An attacker can exploit this vulnerability by
  directly requesting a '.jsp' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to view its source
  code that might reveal sensitive information.");

  script_tag(name:"affected", value:"Caucho Resin version 4.0.36 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121933");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013060064");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/resin_scd.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5144.php");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/resin-doc/viewfile/?file=index.jsp";

if (http_vuln_check(port: port, url: url, pattern: "resin-doc.*default-homepage",
                    extra_check: make_list("getServerName", "hasResinDoc", "hasOrientation"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
