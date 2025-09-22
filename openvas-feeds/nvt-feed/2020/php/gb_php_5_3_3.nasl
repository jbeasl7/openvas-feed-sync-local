# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108869");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2007-1581", "CVE-2010-0397", "CVE-2010-1860", "CVE-2010-1862",
                "CVE-2010-1864", "CVE-2010-1917", "CVE-2010-2097", "CVE-2010-2100",
                "CVE-2010-2101", "CVE-2010-2190", "CVE-2010-2191", "CVE-2010-2225",
                "CVE-2010-2484", "CVE-2010-2531", "CVE-2010-3062", "CVE-2010-3063",
                "CVE-2010-3064", "CVE-2010-3065");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.3.");

  script_tag(name:"solution", value:"Update to version 5.3.3 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38708");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40461");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40948");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41991");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
