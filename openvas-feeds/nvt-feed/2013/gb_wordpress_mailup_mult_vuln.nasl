# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803448");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-2640");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-26 13:22:02 +0530 (Tue, 26 Mar 2013)");
  script_name("WordPress MailUp Plugin Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58467");
  script_xref(name:"URL", value:"http://plugins.trac.wordpress.org/changeset?new=682420");
  script_xref(name:"URL", value:"http://wordpress.org/extend/plugins/wp-mailup/changelog");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  or web script via unspecified vectors in a user's browser session in context
  of an affected site and disclose sensitive information.");
  script_tag(name:"affected", value:"WordPress MailUp Plugin version 1.3.1 and prior");
  script_tag(name:"insight", value:"Not properly restrict access to unspecified Ajax functions in
  ajax.functions.php");
  script_tag(name:"solution", value:"Upgrade WordPress MailUp Plugin 1.3.2 or later.");
  script_tag(name:"summary", value:"WordPress MailUp Plugin is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-mailup/ajax.functions.php?formData=save";

if(http_vuln_check(port:port, url:url,
                   pattern:"<b>Fatal error</b>: .*ajax.functions.php"))
{
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}
