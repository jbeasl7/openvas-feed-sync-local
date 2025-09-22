# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808034");
  script_version("2024-05-07T05:05:33+0000");
  script_cve_id("CVE-2016-4029", "CVE-2016-6634", "CVE-2016-6635");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"creation_date", value:"2016-05-17 10:26:53 +0530 (Tue, 17 May 2016)");
  script_name("WordPress < 4.5 Multiple Vulnerabilities (May 2016) - Windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper validation of HTTP request for detection of valid IP addresses.

  - An insufficient validation in network setting.

  - A script compression option CSRF.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  remote attacker to conduct XSS, CSRF and SSRF bypass attacks.");

  script_tag(name:"affected", value:"WordPress versions prior to 4.5 on Windows.");

  script_tag(name:"solution", value:"Update to WordPress version 4.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92355");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8474");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/8475");
  script_xref(name:"URL", value:"https://codex.wordpress.org/Version_4.5#Security");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"4.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
