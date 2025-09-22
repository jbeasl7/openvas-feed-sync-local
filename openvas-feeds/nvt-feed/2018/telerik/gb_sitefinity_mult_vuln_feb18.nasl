# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:progress:sitefinity";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112222");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-02-13 13:52:34 +0100 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-05 19:58:00 +0000 (Mon, 05 Mar 2018)");

  script_cve_id("CVE-2017-18175", "CVE-2017-18176", "CVE-2017-18177", "CVE-2017-18178",
                "CVE-2017-18179", "CVE-2017-18639");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Progress Sitefinity < 10.1 Multiple Vulnerabilities (Feb 2018)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sitefinity_http_detect.nasl");
  script_mandatory_keys("sitefinity/detected");

  script_tag(name:"summary", value:"Progress Sitefinity is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-18175, CVE-2017-18176, CVE-2017-18177, CVE-2017-18639: Cross-site scripting (XSS)

  - CVE-2017-18178: Open Redirect

  - CVE-2017-18179: Broken Session Management");

  script_tag(name:"affected", value:"Progress Sitefinity versions prior to 10.1.");

  script_tag(name:"solution", value:"Update to version 10.1 or later.");

  script_xref(name:"URL", value:"https://sec-consult.com/vulnerability-lab/advisory/multiple-vulnerabilities-in-progress-sitefinity/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42792");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
