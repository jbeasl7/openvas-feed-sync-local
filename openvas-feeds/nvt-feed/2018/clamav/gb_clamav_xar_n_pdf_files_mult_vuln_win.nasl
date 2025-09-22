# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812577");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2018-03-21 11:04:51 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 16:02:00 +0000 (Tue, 26 Mar 2019)");

  script_cve_id("CVE-2018-0202", "CVE-2018-1000085");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV <= 0.99.3 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-0202: Incorrect handling when parsing certain PDF files

  - CVE-2018-1000085: Incorrect handleding when parsing certain XAR files");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause a
  denial of service and potentially execute arbitrary code on the affected device.");

  script_tag(name:"affected", value:"ClamAV version 0.99.3 and prior.");

  script_tag(name:"solution", value:"Update to version 0.99.4 or later.");

  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav-devel/commit/d96a6b8bcc7439fa7e3876207aa0a8e79c8451b6");

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

if (version_is_less(version: version, test_version: "0.99.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.99.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
