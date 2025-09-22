# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809779");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-9296", "CVE-2014-9295");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-01-16 17:05:06 +0530 (Mon, 16 Jan 2017)");
  script_name("NTP.org 'ntpd' Multiple Vulnerabilities (Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/852879");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71758");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71761");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2668");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2667");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2669");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2670");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An error in the 'receive' function in ntp_proto.c script within application
  which continues to execute even after detecting a certain authentication error.

  - Multiple errors in ntpd functions 'crypto_recv' (when using autokey
  authentication), 'ctl_putdata', and 'configure'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and other unspecified effect on the affected
  system.");

  script_tag(name:"affected", value:"NTPd version prior to 4.2.8.");

  script_tag(name:"solution", value:"Update to version 4.2.8 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
