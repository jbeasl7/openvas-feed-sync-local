# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107200");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2017-05-22 17:40:57 +0200 (Mon, 22 May 2017)");
  script_cve_id("CVE-2017-9061", "CVE-2017-9062", "CVE-2017-9063", "CVE-2017-9064", "CVE-2017-9065", "CVE-2017-9066");

  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-15 12:35:00 +0000 (Fri, 15 Mar 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress < 4.7.5 Multiple Security Vulnerabilities - Windows");
  script_tag(name:"summary", value:"WordPress is prone to the following security vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WordPress is prone to the following security vulnerabilities:

  1. An open-redirect vulnerability

  2. Multiple security bypass vulnerabilities

  3. Multiple cross-site scripting vulnerabilities

  4. A cross-site request-forgery vulnerability");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute HTML and script
  code in  the browser of an unsuspecting user in the context of the affected  site, perform certain
  unauthorized actions actions, or bypass certain  security restrictions.");

  script_tag(name:"affected", value:"WordPress prior to 4.7.5 versions are vulnerable");

  script_tag(name:"solution", value:"Update to 4.7.5.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98509");

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

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port: Port)){
  exit(0);
}

if(version_is_less(version:Ver, test_version:"4.7.5")){
  report = report_fixed_ver(installed_version:Ver, fixed_version:"4.7.5");
  security_message(port:Port, data:report);
  exit(0);
}

exit(99);
