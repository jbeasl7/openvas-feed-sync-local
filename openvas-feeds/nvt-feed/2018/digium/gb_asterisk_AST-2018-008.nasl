# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141178");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-06-13 10:18:20 +0700 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-29 16:22:00 +0000 (Fri, 29 Mar 2019)");

  script_cve_id("CVE-2018-12227");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Information Disclosure Vulnerability (AST-2018-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When endpoint specific ACL rules block a SIP request they respond
  with a 403 forbidden. However, if an endpoint is not identified then a 401 unauthorized response is
  sent. This vulnerability just discloses which requests hit a defined endpoint. The ACL rules cannot
  be bypassed to gain access to the disclosed endpoints.");

  script_tag(name:"affected", value:"Asterisk Open Source versions 13.x, 14.x, 15.x, Certified
  Asterisk versions 13.18 and 13.21.");

  script_tag(name:"solution", value:"Update to version 13.21.1, 14.7.7, 15.4.1, 13.18-cert4,
  13.21-cert2 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-008.html");
  script_xref(name:"URL", value:"https://issues.asterisk.org/jira/browse/ASTERISK-27818");

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
    if (revcomp(a: version, b: "13.18cert4") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18-cert4");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else if (version =~ "^13\.21cert") {
    if (revcomp(a: version, b: "13.21cert2") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21-cert2");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_in_range(version: version, test_version: "13.10.0", test_version2: "13.21.0")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.21.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.7");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.4.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
