# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140792");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-02-22 11:26:42 +0700 (Thu, 22 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 18:54:00 +0000 (Fri, 01 Mar 2019)");

  script_cve_id("CVE-2018-7284", "CVE-2018-7286");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk is prone to multiple vulnerabilities:

  - Crash when given an invalid SDP media format description

  - Crash with an invalid SDP fmtp attribute

  - Crash when receiving SUBSCRIBE request (CVE-2018-7284)

  - Crash when large numbers of TCP connections are closed suddenly (CVE-2018-7286)");

  script_tag(name:"affected", value:"Asterisk Open Source versions 13.x, 14.x, 15.x and Certified
  Asterisk 13.18.");

  script_tag(name:"solution", value:"Update to version 13.19.2, 14.7.6, 15.2.2, 13.18-cert3
  or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-002.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-003.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-004.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-005.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if (version =~ "^13\.18cert") {
    if (revcomp(a: version, b: "13.18cert3") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18-cert3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.19.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.19.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.6");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.2.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.2.2");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
