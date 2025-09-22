# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805985");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-3439");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-12 13:03:09 +0530 (Mon, 12 Oct 2015)");
  script_name("WordPress plupload Cross-Site Scripting Vulnerability - Windows");

  script_tag(name:"summary", value:"WordPress is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the Ephox
  plupload.flash.swf in Plupload which does not sanitize user input via 'target'
  GET parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"WordPress version 3.9.x, 4.0.x, and 4.1.x
  before 4.1.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 4.1.2 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://wordpress.org/news/2015/04/wordpress-4-1-2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74269");
  script_xref(name:"URL", value:"http://zoczus.blogspot.in/2015/04/plupload-same-origin-method-execution.html");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

if(wpVer =~ "^(3\.9\.)" ||
   wpVer =~ "^(4\.0\.)" ||
   version_in_range(version:wpVer, test_version:"4.1.0", test_version2:"4.1.1"))
{
  report = 'Installed Version: ' + wpVer + '\n' +
           'Fixed Version:     ' + "4.1.2" + '\n';

  security_message(data:report, port:wpPort);
  exit(0);
}
