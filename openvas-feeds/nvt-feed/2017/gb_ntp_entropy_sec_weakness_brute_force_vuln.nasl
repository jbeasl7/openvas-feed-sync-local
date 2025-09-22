# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809781");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-9293");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-01-16 17:55:06 +0530 (Mon, 16 Jan 2017)");
  script_name("NTP.org 'ntpd' Insufficient Entropy Security Weakness Brute Force Attack Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/852879");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71757");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2665");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to a brute force attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in 'config_auth'
  function in ntpd when an auth key is not configured, improperly generates a key
  and makes it easier for remote attackers to conduct brute force attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to defeat cryptographic protection mechanisms via a brute-force attack.");

  script_tag(name:"affected", value:"NTPd version prior to 4.2.7p11.");

  script_tag(name:"solution", value:"Update to version 4.2.7p11 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

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

if (revcomp(a: version, b: "4.2.7p11") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.7p11", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
