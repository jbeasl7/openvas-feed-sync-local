# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150702");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-06-21 09:34:21 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 00:00:00 +0000 (Wed, 20 Jan 2021)");

  script_cve_id("CVE-2020-15025");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP < 4.2.8p15 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_tag(name:"summary", value:"Systems that use a CMAC algorithm in ntp.keys will not release a
  bit of memory on each packet that uses a CMAC keyid, eventually causing ntpd to run out of memory
  and fail. The CMAC cleanup introduced a bug whereby the CMAC data structure was no longer
  completely removed.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"NTPd version prior to 4.2.8p15, 4.3.x prior to version 4.3.101.");

  script_tag(name:"solution", value:"Update to version 4.2.8p15, 4.3.101 or later.");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3661");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.2.8p15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p15", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.3.97", test_version2: "4.3.100")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.101", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
