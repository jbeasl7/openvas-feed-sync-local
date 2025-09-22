# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813578");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-07-17 15:54:58 +0530 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)");

  script_cve_id("CVE-2018-0360", "CVE-2018-0361");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV < 0.100.1 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-0360: HWP integer overflow error in function 'parsehwp3_paragraph' in file
  libclamav/hwp.c.

  - CVE-2018-0361: Lack of PDF object length check");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause denial
  of service and lengthen file parsing time.");

  script_tag(name:"affected", value:"ClamAV versions prior to 0.100.1.");

  script_tag(name:"solution", value:"Update to version 0.100.1 or later.");

  script_xref(name:"URL", value:"https://blog.clamav.net/2018/07/clamav-01001-has-been-released.html");
  script_xref(name:"URL", value:"https://secuniaresearch.flexerasoftware.com/secunia_research/2018-12/");

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

if (version_is_less(version: version, test_version: "0.100.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.100.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
