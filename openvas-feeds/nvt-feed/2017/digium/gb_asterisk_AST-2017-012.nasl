# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140600");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-12-14 08:55:37 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-02 17:35:00 +0000 (Tue, 02 Jan 2018)");

  script_cve_id("CVE-2017-17664");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If a compound RTCP packet is received containing more than one
  report (for example a Receiver Report and a Sender Report) the RTCP stack will incorrectly store
  report information outside of allocated memory potentially causing a crash.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x, 15.x and Certified Asterisk
  13.13.");

  script_tag(name:"solution", value:"Update to version 13.18.4, 14.7.4, 15.1.4, 13.13-cert9 or
  later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-012.html");

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
  if (version =~ "^13\.13cert") {
    if (revcomp(a: version, b: "13.13cert9") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.13-cert9");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_less(version: version, test_version: "13.18.4")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18.4");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.4");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1.4");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
