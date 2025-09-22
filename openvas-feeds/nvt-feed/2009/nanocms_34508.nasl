# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nanocms:nanocms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100141");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("NanoCMS '/data/pagesdata.txt' Password Hash Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("nanocms_detect.nasl");
  script_mandatory_keys("nanocms/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34508");

  script_tag(name:"summary", value:"NanoCMS is prone to an information disclosure vulnerability because
  it fails to validate access to sensitive files.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"NanoCMS 0.4_final is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/data/pagesdata.txt";

if (http_vuln_check(port: port, url: url, pattern: "password.*[a-f0-9]{32}", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
