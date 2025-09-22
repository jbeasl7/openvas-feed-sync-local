# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812790");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2018-7182", "CVE-2018-7183");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-03-07 11:25:49 +0530 (Wed, 07 Mar 2018)");
  script_name("NTP.org 'ntpd' 'ctl_getitem()' And 'decodearr()' Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3412");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103191");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/103351");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3414");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#February_2018_ntp_4_2_8p11_NTP_S");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An error in 'ctl_getitem()' which is used by ntpd to process incoming mode
  6 packets. A malicious mode 6 packet can be sent to an ntpd instance,
  will cause 'ctl_getitem()' to read past the end of its buffer.

  - An error in 'decodearr()' which is used by ntpq can write beyond its buffer limit.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and obtain sensitive information that may lead to
  further attacks.");

  script_tag(name:"affected", value:"NTPd version starting from 4.2.8p6 and prior to 4.2.8p11.");

  script_tag(name:"solution", value:"Update to version 4.2.8p11 or later.");

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

if (version =~ "^4\.2\.8") {
  if ((revcomp(a: version, b: "4.2.8p6") >= 0) && (revcomp(a: version, b: "4.2.8p11") < 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p11", install_path: location);
    security_message(port: port, proto: proto, data: report);
    exit(0);
  }
}

exit(99);
