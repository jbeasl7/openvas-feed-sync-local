# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140495");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-11-09 10:52:58 +0700 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-16672");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Memory Leak Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a memory/RTP/file descriptor leak
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A memory leak occurs when an Asterisk pjsip session object is
  created and that call gets rejected before the session itself is fully established. When this
  happens the session object never gets destroyed. This then leads to file descriptors and RTP ports
  being leaked as well.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x, 15.x and Certified Asterisk
  13.13.");

  script_tag(name:"solution", value:"Update to version 13.18.1, 14.7.1, 15.1.1, 13.13-cert7 or
  later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-011.html");

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
    if (revcomp(a: version, b: "13.13cert7") < 0) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.13-cert7");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
  else {
    if (version_is_greater_equal(version: version, test_version: "13.5.0") &&
        version_is_less(version: version, test_version: "13.18.1")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "13.18.1");
      security_message(port: port, data: report, proto: "udp");
      exit(0);
    }
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.7.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.7.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.1.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.1.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
