# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112147");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-12-04 14:49:33 +0100 (Mon, 04 Dec 2017)");
  script_cve_id("CVE-2017-17091", "CVE-2017-17092", "CVE-2017-17093", "CVE-2017-17094");

  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress < 4.9.1 Multiple Vulnerabilities - Windows");
  script_tag(name:"summary", value:"WordPress prior to 4.9.1 is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress before 4.9.1 is prone to the following security vulnerabilities:

  - wp-admin/user-new.php sets the newbloguser key to a string that can be directly derived from the user ID,
which allows remote attackers to bypass intended access restrictions by entering this string. (CVE-2017-17091)

  - wp-includes/functions.php does not require the unfiltered_html capability for upload of .js files,
which might allow remote attackers to conduct XSS attacks via a crafted file. (CVE-2017-17092)

  - wp-includes/general-template.php does not properly restrict the lang attribute of an HTML element,
which might allow attackers to conduct XSS attacks via the language setting of a site. (CVE-2017-17093)

  - wp-includes/feed.php does not properly restrict enclosures in RSS and Atom fields,
which might allow attackers to conduct XSS attacks via a crafted URL. (CVE-2017-17094)");

  script_tag(name:"impact", value:"An attacker may leverage these issues to bypass access restrictions or conduct XSS via specific vectors.");

  script_tag(name:"affected", value:"WordPress prior to version 4.9.1.");

  script_tag(name:"solution", value:"Update to WordPress 4.9.1 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/news/2017/11/wordpress-4-9-1-security-and-maintenance-release/");
  script_xref(name:"URL", value:"https://codex.wordpress.org/Version_4.9.1");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Web application abuses");

  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(version_is_less(version:ver, test_version:"4.9.1"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.9.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
