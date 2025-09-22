# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104669");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2023-04-12 12:32:58 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-24 13:58:00 +0000 (Mon, 24 Apr 2023)");

  script_cve_id("CVE-2023-26551", "CVE-2023-26552", "CVE-2023-26553", "CVE-2023-26554", "CVE-2023-26555");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP <= 4.2.8p15 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_tag(name:"summary", value:"NTP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2023-26551: mstolfp in libntp/mstolfp.c has an out-of-bounds write in the cp<cpdec while
  loop. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.

  - CVE-2023-26552: mstolfp in libntp/mstolfp.c has an out-of-bounds write when adding a decimal
  point. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.

  - CVE-2023-26553: mstolfp in libntp/mstolfp.c has an out-of-bounds write when copying the trailing
  number. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.

  - CVE-2023-26554: mstolfp in libntp/mstolfp.c has an out-of-bounds write when adding a '\0'
  character. An adversary may be able to attack a client ntpq process, but cannot attack ntpd.

  - CVE-2023-26555: praecis_parse in ntpd/refclock_palisade.c has an out-of-bounds write. Any attack
  method would be complex, e.g., with a manipulated GPS receiver.");

  script_tag(name:"affected", value:"NTPd version 4.2.8p15 and prior.");

  script_tag(name:"solution", value:"Update to version 4.2.8p16 or later.");

  script_xref(name:"URL", value:"https://www.ntp.org/support/securitynotice/4_2_8p16-release-announcement/");
  script_xref(name:"URL", value:"https://www.ntp.org/support/securitynotice/#428p16");
  script_xref(name:"URL", value:"https://github.com/spwpun/ntp-4.2.8p15-cves");
  script_xref(name:"URL", value:"https://github.com/spwpun/ntp-4.2.8p15-cves/issues/1");

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

if (version_is_less_equal(version: version, test_version: "4.2.8p15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p16", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
