# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811253");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-7703");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 18:21:00 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"creation_date", value:"2017-07-25 11:30:12 +0530 (Tue, 25 Jul 2017)");
  script_name("NTP.org 'ntpd' ':config' Command Arbitrary File Overwrite Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug2902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77278");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to an arbitrary file-overwrite vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper access
  restrictions for the 'pidfile' or 'driftfile' directives in NTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to send remote configuration requests, and if the attacker knows
  the remote configuration password, it's possible for an attacker to use
  the 'pidfile' or 'driftfile' directives to potentially overwrite other
  files.");

  script_tag(name:"affected", value:"NTPd version 4.x prior to 4.2.8p4 and 4.3.0 prior to
  4.3.77.");

  script_tag(name:"solution", value:"Update to version 4.2.8p4, 4.3.77 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version =~ "^4\.[0-2]") {
  if (revcomp(a: version, b: "4.2.8p4") < 0) {
    fix = "4.2.8p4";
  }
}

else if (version =~ "^4\.3") {
  if (revcomp(a: version, b: "4.3.77") < 0) {
    fix = "4.3.77";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
