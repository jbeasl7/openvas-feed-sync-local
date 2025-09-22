# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108870");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2020-08-17 06:44:26 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2006-7243", "CVE-2010-2094", "CVE-2010-2950", "CVE-2010-3436",
                "CVE-2010-3709", "CVE-2010-3710", "CVE-2010-3870", "CVE-2010-4150",
                "CVE-2010-4156", "CVE-2010-4409", "CVE-2010-4697", "CVE-2010-4698",
                "CVE-2010-4699", "CVE-2010-4700", "CVE-2011-0753", "CVE-2011-0754",
                "CVE-2011-0755");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PHP prior to version 5.3.4.");

  script_tag(name:"solution", value:"Update to version 5.3.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44723");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44951");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45335");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45339");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45952");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45954");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46168");

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

if (version_is_less(version: version, test_version: "5.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
