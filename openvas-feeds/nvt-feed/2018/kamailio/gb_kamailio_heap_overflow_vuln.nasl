# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kamailio:kamailio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140938");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-04-03 15:52:17 +0700 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2018-8828");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kamailio < 4.4.7, 5.x < 5.0.6, 5.1.x < 5.1.2 Heap Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_kamailio_sip_detect.nasl");
  script_mandatory_keys("kamailio/detected");

  script_tag(name:"summary", value:"Kamailio is prone to a heap overflow vulnerability which may
  result in a denial of service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A specially crafted REGISTER message with a malformed branch or
  From tag triggers an off-by-one heap overflow.");

  script_tag(name:"affected", value:"Kamailio versions 4.4.x, 5.0.x and 5.1.x.");

  script_tag(name:"solution", value:"Update to version 4.4.7, 5.0.6, 5.1.2 or later.");

  script_xref(name:"URL", value:"https://www.kamailio.org/w/2018/03/kamailio-security-announcement-tmx-lcr/");
  script_xref(name:"URL", value:"https://github.com/EnableSecurity/advisories/tree/master/ES2018-05-kamailio-heap-overflow");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less(version: version, test_version: "4.4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.7");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.6");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.2");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(0);
