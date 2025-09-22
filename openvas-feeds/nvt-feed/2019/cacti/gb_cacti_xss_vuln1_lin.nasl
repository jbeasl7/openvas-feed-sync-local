# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141887");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-01-18 09:06:27 +0700 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-24 13:01:00 +0000 (Tue, 24 May 2022)");

  script_cve_id("CVE-2018-10059", "CVE-2018-10060", "CVE-2018-10061");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.1.37 Multiple XSS Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cacti is prone to multiple cross-site scripting vulnerabilities:

  - XSS because the get_current_page function in lib/functions.php relies on $_SERVER['PHP_SELF'] instead of
    $_SERVER['SCRIPT_NAME'] to determine a page name (CVE-2018-10059)

  - XSS because it does not properly reject unintended characters, related to use of the sanitize_uri function in
    lib/functions.php (CVE-2018-10060)

  - XSS because it makes certain htmlspecialchars calls without the ENT_QUOTES flag (CVE-2018-10061)");

  script_tag(name:"affected", value:"Cacti version 1.1.36 and prior.");

  script_tag(name:"solution", value:"Update to version 1.1.37 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/1457");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.1.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.1.37");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
