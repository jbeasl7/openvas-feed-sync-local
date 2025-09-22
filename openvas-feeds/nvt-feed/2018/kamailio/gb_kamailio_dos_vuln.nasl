# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kamailio:kamailio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112340");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-04-03 15:52:17 +0700 (Tue, 03 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-04 21:29:00 +0000 (Thu, 04 Oct 2018)");

  script_cve_id("CVE-2018-14767", "CVE-2018-16657");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kamailio < 5.0.7 & 5.1.x < 5.1.4 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_kamailio_sip_detect.nasl");
  script_mandatory_keys("kamailio/detected");

  script_tag(name:"summary", value:"Kamailio is prone to multiple denial of service vulnerabilities
  which may result in a crash of the system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-14767: A security vulnerability in the Kamailio SIP server related to the 'To' header
  processing. A specially crafted SIP message with double To header and an empty To tag causes a
  segmentation fault and crashes Kamailio. The reason is missing input validation in the
  build_res_buf_from_sip_req core function.

  - CVE-2018-16657: A security vulnerability in the Kamailio core related to Via header processing.
  A specially crafted SIP message with an invalid Via header causes a segmentation fault and crashes
  Kamailio. The reason is missing input validation in the crcitt_string_array core function for
  calculating a CRC hash for To tags. An additional error is present in the check_via_address core
  function, this function also misses input validation.");

  script_tag(name:"impact", value:"Abuse of this vulnerability leads to denial of service in Kamailio.
  Further research may show that exploitation leads to remote code execution. This vulnerability is
  rather old and will probably also apply to older versions of Kamailio and maybe even OpenSER.");

  script_tag(name:"affected", value:"Kamailio versions before 5.0.7 and 5.1.x before 5.1.4.");

  script_tag(name:"solution", value:"Apply the patch from github or make use of a release that
  includes that patch (e.g. 5.1.4 or 5.0.7). At the moment no workarounds (e.g. in the configuration)
  are known.");

  script_xref(name:"URL", value:"https://www.kamailio.org/w/2018/07/kamailio-security-announcement-for-kamailio-core/");
  script_xref(name:"URL", value:"https://skalatan.de/blog/advisory-hw-2018-05");
  script_xref(name:"URL", value:"https://skalatan.de/blog/advisory-hw-2018-06");
  script_xref(name:"URL", value:"https://github.com/kamailio/kamailio/commit/281a6c6b6eaaf30058b603325e8ded20b99e1456");

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

if (version_is_less(version: version, test_version: "5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.7");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.1", test_version2: "5.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.4");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
