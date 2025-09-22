# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140791");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2018-02-22 11:18:04 +0700 (Thu, 22 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-21 12:56:00 +0000 (Wed, 21 Mar 2018)");

  script_cve_id("CVE-2018-7285", "CVE-2018-7287");

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

  - Crash when receiving unnegotiated dynamic payload (CVE-2018-7285)

  - WebSocket frames with 0 sized payload causes DoS (CVE-2018-7287)");

  script_tag(name:"affected", value:"Asterisk Open Source versions 15.x.");

  script_tag(name:"solution", value:"Update to version 15.2.2 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-001.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2018-006.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^15\.") {
  if (version_is_less(version: version, test_version: "15.2.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "15.2.2");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
