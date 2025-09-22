# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200010");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2005-3740");

  script_name("PHP-Fusion <= 6.00.206 Forum SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"solution", value:"Apply the patch from the php-fusion main site.");

  script_tag(name:"summary", value:"A vulnerability is reported in the forum module of PHP-Fusion
  6.00.206 and some early released versions.");

  script_tag(name:"impact", value:"When the forum module is activated, a registered user can execute
  arbitrary SQL injection commands.");

  script_tag(name:"insight", value:"The failure exists because the application does not properly sanitize
  user-supplied input in 'options.php' and 'viewforum.php' before using it in the SQL query, and
  magic_quotes_gpc is set to off.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15502");
  script_xref(name:"URL", value:"http://secunia.com/advisories/17664/");
  script_xref(name:"URL", value:"http://www.php-fusion.co.uk/downloads.php?cat_id=3");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version:"6.00.206")){
  report = report_fixed_ver(installed_version:version, fixed_version:"Apply patch", install_path:location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
