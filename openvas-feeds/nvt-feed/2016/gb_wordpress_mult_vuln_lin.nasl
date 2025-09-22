# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807060");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-02-08 14:40:48 +0530 (Mon, 08 Feb 2016)");
  script_name("WordPress Core Multiple Vulnerabilities (Feb 2016) - Linux");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to insufficient
  validation requests.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing.");

  script_tag(name:"affected", value:"WordPress versions 3.7.x, through 3.7.12,
  3.8.x through 3.8.12, 3.9.x through 3.9.10, 4.0.x through 4.1.9, 4.2.x through
  4.2.6 and 4.3.x through 4.3.2 and 4.4.x through 4.4.1 on Linux.");

  script_tag(name:"solution", value:"Update to WordPress version 3.7.13 or
  3.8.13 or 3.9.11 or 4.1.10 or 4.2.7 or 4.3.3 or 4.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8376");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8377");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");
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

if(version_in_range(version:wpVer, test_version:"3.7", test_version2:"3.7.12"))
{
  fix = "3.7.13";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"3.8", test_version2:"3.8.12"))
{
  fix = "3.8.13";
  VULN = TRUE;
}

else if(version_in_range(version:wpVer, test_version:"3.9", test_version2:"3.9.10"))
{
  fix = "3.9.11";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.0", test_version2:"4.0.9"))
{
  fix = "4.0.10";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.1", test_version2:"4.1.9"))
{
  fix = "4.1.10";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.2", test_version2:"4.2.6"))
{
  fix = "4.2.7";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.3", test_version2:"4.3.2"))
{
  fix = "4.3.3";
  VULN = TRUE;
}
else if(version_in_range(version:wpVer, test_version:"4.4", test_version2:"4.4.1"))
{
  fix = "4.4.2";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:fix);
  security_message(data:report, port:wpPort);
  exit(0);
}
