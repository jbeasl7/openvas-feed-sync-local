# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106173");
  script_version("2023-12-20T12:22:41+0000");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-08-08 16:53:09 +0700 (Mon, 08 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-3008");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk TLS Certificate Common Name NULL Byte Vulnerability (AST-2015-003)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a certificate bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Asterisk does not properly handle a null byte in a domain name
  in the subject's Common Name (CN) field of an X.509 certificate, when registering a SIP TLS device.
  This allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate
  issued by a legitimate Certification Authority.");

  script_tag(name:"impact", value:"A man-in-the-middle attcker may spoof arbitrary SSL servers.");

  script_tag(name:"affected", value:"Asterisk Open Source 1.8 before 1.8.32.3, 11.x before 11.17.1,
  12.x before 12.8.2, and 13.x before 13.3.2 and Certified Asterisk 1.8.28 before 1.8.28-cert5, 11.6
  before 11.6-cert11, and 13.1 before 13.1-cert2.");

  script_tag(name:"solution", value:"Update to version 1.8.32.3, 11.17.1, 12.8.2, 13.3.2,
  1.8.28-cert5, 11.6-cert11, 13.1-cert2 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2015-003.html");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^1\.8") {
  if (version =~ "^1\.8\.28cert") {
    if (revcomp(a: version, b: "1.8.28cert5") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "1.8.25-cert5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "1.8.32.3")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "1.8.32.3");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^11\.") {
  if (version =~ "^11\.6cert") {
    if (revcomp(a: version, b: "11.6cert11") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.6-cert11");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "11.17.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "11.17.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^12\.") {
  if (version_is_less(version: version, test_version: "12.8.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "12.8.2");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^13\.") {
  if (version =~ "^13\.1cert") {
    if (revcomp(a: version, b: "13.1cert2") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.1-cert2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.3.2")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.3.2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

exit(0);
