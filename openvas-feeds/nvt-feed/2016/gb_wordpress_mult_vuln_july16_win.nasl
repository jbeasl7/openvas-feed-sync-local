# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808255");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-5832", "CVE-2016-5833", "CVE-2016-5834", "CVE-2016-5835",
                "CVE-2016-5836", "CVE-2016-5837", "CVE-2016-5838", "CVE-2016-5839");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-30 03:07:00 +0000 (Wed, 30 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-07-20 15:37:55 +0530 (Wed, 20 Jul 2016)");
  script_name("WordPress Multiple Vulnerabilities (Jul 2016) - Windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient validation of user supplied input via attachment name in
    the column_title function in 'wp-admin/includes/class-wp-media-list-table.php'
    script.

  - An error related to 'wp-admin/includes/ajax-actions.php' and
    'wp-admin/revision.php' scripts.

  - An error in customizer.

  - An insufficient validation of user supplied input via attachment name in
    the wp_get_attachment_link function in 'wp-includes/post-template.php'
    script.

  - An error in 'oEmbed' protocol implementation.

  - Other multiple unspecified errors.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attacker to inject arbitrary web script or HTML, obtain sensitive
  information, bypass intended redirection restrictions, cause a denial
  of service and bypass intended password-change restrictions.");

  script_tag(name:"affected", value:"WordPress versions prior to 4.5.3 on Windows.");

  script_tag(name:"solution", value:"Update to WordPress version 4.5.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://wordpress.org/news/2016/06/wordpress-4-5-3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91362");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91368");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91366");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91363");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91365");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91364");
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:wpVer, test_version:"4.5.3"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.5.3");
  security_message(data:report, port:wpPort);
  exit(0);
}
