# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140494");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2017-11-09 10:34:31 +0700 (Thu, 09 Nov 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-25 11:29:00 +0000 (Sun, 25 Nov 2018)");

  script_cve_id("CVE-2017-16671");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk CDR Buffer Overflow Vulnerability (AST-2017-010)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a buffer overflow vulnerability in CDR's
  set user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"No size checking is done when setting the user field for Party B
  on a CDR. Thus, it is possible for someone to use an arbitrarily large string and write past the
  end of the user field storage buffer.

  This currently affects any system using CDR's that also make use of the following:

  - The 'X-ClientCode' header within a SIP INFO message when using chan_sip and the 'useclientcode'
  option is enabled (note, it's disabled by default).

  - The CDR dialplan function executed from AMI when setting the user field.

  - The AMI Monitor action when using a long file name/path.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.x, 14.x, 15.x and Certified Asterisk
  13.13.");

  script_tag(name:"solution", value:"Update to version 13.18.1, 14.7.1, 15.1.1, 13.13-cert7 or
  later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-010.html");

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
    if (version_is_less(version: version, test_version: "13.18.1")) {
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
