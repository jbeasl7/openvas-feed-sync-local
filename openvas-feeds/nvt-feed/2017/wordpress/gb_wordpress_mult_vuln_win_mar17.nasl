# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809895");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2017-6804", "CVE-2017-6815", "CVE-2017-6814", "CVE-2017-6816",
                "CVE-2017-6818", "CVE-2017-6817", "CVE-2017-6819");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-19 12:54:00 +0000 (Tue, 19 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-03-07 15:00:55 +0530 (Tue, 07 Mar 2017)");
  script_name("WordPress Multiple Vulnerabilities (Mar 2017) - Windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A cross-site scripting (XSS) vulnerability in media file metadata.

  - An improper URL validation.

  - Unintended files can be deleted by administrators using the plugin deletion
    functionality.

  - A cross-site scripting (XSS) in video URL in YouTube embeds.

  - A Cross-site request forgery (CSRF) in Press.");

  script_tag(name:"impact", value:"Successfully exploiting will allow remote
  attacker to create a specially crafted URL, execute arbitrary script code
  in an user's browser session within the trust relationship between their
  browser and the server and leading to excessive use of server resources.");

  script_tag(name:"affected", value:"WordPress versions 4.7.2 and prior on Windows.");

  script_tag(name:"solution", value:"Update to WordPress version 4.7.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/03/wordpress-4-7-3-security-and-maintenance-release");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(version_is_less(version:wpVer, test_version:"4.7.3"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.7.3");
  security_message(data:report, port:wpPort);
  exit(0);
}
