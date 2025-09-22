# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808037");
  script_version("2024-05-07T05:05:33+0000");
  script_cve_id("CVE-2016-4566", "CVE-2016-4567");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-23 15:23:53 +0000 (Mon, 23 May 2016)");
  script_tag(name:"creation_date", value:"2016-05-17 12:35:57 +0530 (Tue, 17 May 2016)");
  script_name("WordPress < 4.5.2 Multiple XSS Vulnerabilities (May 2016) - Linux");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://wordpress.org/news/2016/05/wordpress-4-5-2/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2016/05/07/2");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-452-cross-site-scripting-via-mediaelementjs");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-452-cross-site-scripting-via-pluploadflashswf");

  script_tag(name:"summary", value:"WordPress is prone to multiple cross-site scripting (XSS)
  vulnerabilities in third-party libraries.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws in third-party libraries exist:

  - CVE-2016-4566: XSS vulnerability in plupload.flash.swf in Plupload before 2.1.9

  - CVE-2016-4567: XSS vulnerability in flash/FlashMediaElement.as in MediaElement.js before
  2.21.0");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attacker to
  execute arbitrary script code in a user's browser session within the trust relationship.");

  script_tag(name:"affected", value:"- CVE-2016-4566: Versions through 4.5.1

  - CVE-2016-4567: Versions 4.2.x through 4.5.1");

  script_tag(name:"solution", value:"Update to version 4.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"4.5.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
