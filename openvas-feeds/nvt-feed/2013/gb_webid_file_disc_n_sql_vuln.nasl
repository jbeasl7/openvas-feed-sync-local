# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webidsupport:webid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803399");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-05-09 17:11:32 +0530 (Thu, 09 May 2013)");
  script_name("WeBid Local File Disclosure and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://1337day.com/exploit/20730");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25249");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/webid-106-file-disclosure-sql-injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_webid_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webid/installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to perform file
disclosure attacks and read arbitrary files on the affected application or
perform SQL injection and compromise the application.");
  script_tag(name:"affected", value:"WeBid version 1.0.6 and prior");
  script_tag(name:"insight", value:"The flaws are due to improper input validation:

  - Input passed via the 'js' parameter to loader.php, allows attackers to
read arbitrary files.

  - $_POST['startnow'] is directly used in mysql query without sanitization
in yourauctions_p.php.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"WeBid is prone to file disclosure and SQL Injection vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files();

foreach file (keys(files))
{
  url = dir + "/loader.php?js=" + files[file];

  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_message(port);
    exit(0);
  }
}
