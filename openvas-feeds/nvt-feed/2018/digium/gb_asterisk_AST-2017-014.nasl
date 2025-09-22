# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140648");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-01-04 12:06:46 +0700 (Thu, 04 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-25 11:29:00 +0000 (Sun, 25 Nov 2018)");

  script_cve_id("CVE-2017-17850");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A select set of SIP messages create a dialog in Asterisk. Those
  SIP messages must contain a contact header. For those messages, if the header was not present and
  using the PJSIP channel driver, it would cause Asterisk to crash. The severity of this vulnerability
  is somewhat mitigated if authentication is enabled. If authentication is enabled a user would have
  to first be authorized before reaching the crash point.");

  script_tag(name:"affected", value:"Asterisk Open Source versions 13.x, 14.x, 15.x and Certified
  Asterisk version 13.18.");

  script_tag(name:"solution", value:"Update to version 13.18.5, 14.7.5, 15.1.5, 13.18-cert2 or
  later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-014.html");

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
    if (revcomp(a: version, b: "13.18cert2") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18-cert2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.18.5")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18.5");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.5");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.1.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1.5");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
