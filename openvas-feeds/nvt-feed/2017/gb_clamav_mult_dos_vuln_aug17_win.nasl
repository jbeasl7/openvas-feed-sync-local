# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811575");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-08-08 14:13:11 +0530 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)");

  script_cve_id("CVE-2017-11423", "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ClamAV <= 0.99.2 Multiple DoS Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2017-6419: Improper validation of CHM files in 'mspack/lzxd.c' script in libmspack 0.5alpha.

  - CVE-2017-11423: Improper validation of CAB files in cabd_read_string function in 'mspack/cabd.c'
  script in libmspack 0.5alpha.

  - CVE-2017-6418: Improper validation for e-mail message in 'libclamav/message.c' script.

  - CVE-2017-6420: Improper validation of PE files in wwunpack function in 'libclamav/wwunpack.c'
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to cause a
  denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"ClamAV version 0.99.2 and prior.");

  script_tag(name:"solution", value:"Update to version 0.99.3-beta1.");

  script_xref(name:"URL", value:"https://github.com/vrtadmin/clamav-devel/commit/a83773682e856ad6529ba6db8d1792e6d515d7f1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100154");

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

if (version_is_less_equal(version: version, test_version: "0.99.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.99.3-beta1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
