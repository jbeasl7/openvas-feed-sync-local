# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108866");
  script_version("2025-05-02T15:41:40+0000");
  script_tag(name:"last_modification", value:"2025-05-02 15:41:40 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 03:29:57 +0000 (Thu, 15 Feb 2024)");

  script_cve_id("CVE-2007-3996", "CVE-2007-4782", "CVE-2007-4783", "CVE-2007-4784",
                "CVE-2007-4825", "CVE-2007-4840", "CVE-2007-4887", "CVE-2007-4889",
                "CVE-2007-5447", "CVE-2007-5653", "CVE-2007-5898", "CVE-2007-5899",
                "CVE-2007-5900", "CVE-2008-2107", "CVE-2008-2108", "CVE-2008-4107");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.2.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP before version 5.2.5.");

  script_tag(name:"solution", value:"Update to version 5.2.5 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26403");

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

if (version_is_less(version: version, test_version: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
