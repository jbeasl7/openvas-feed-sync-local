# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801994");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)");
  script_cve_id("CVE-2011-3646");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("phpMyAdmin Information Disclosure Vulnerability (PMASA-2011-15) - Active Check");
  script_xref(name:"URL", value:"http://www.auscert.org.au/render.html?it=14975");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Oct/690");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=746882");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2011-15.php");
  script_xref(name:"URL", value:"http://phpmyadmin.git.sourceforge.net/git/gitweb.cgi?p=phpmyadmin/phpmyadmin;a=commitdiff;h=d35cba980893aa6e6455fd6e6f14f3e3f1204c52");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"phpMyAdmin version 3.4.5 and prior.");

  script_tag(name:"insight", value:"The flaw is due to insufficient input validation in 'js_frame'
  parameter in 'phpmyadmin.css.php', which allows attackers to disclose information that could be
  used in further attacks.");

  script_tag(name:"solution", value:"Update to version 3.4.6 or later.");

  script_tag(name:"summary", value:"phpMyAdmin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/phpmyadmin.css.php?js_frame[]=right";

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"Cannot modify header information.*/phpmyadmin\.css\.php")) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
