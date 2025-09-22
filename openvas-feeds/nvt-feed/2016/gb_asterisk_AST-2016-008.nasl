# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106461");
  script_version("2023-12-20T12:22:41+0000");
  script_cve_id("CVE-2016-9937");
  script_tag(name:"last_modification", value:"2023-12-20 12:22:41 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-12-09 14:10:48 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-27 01:29:00 +0000 (Thu, 27 Jul 2017)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk SDP Offer DoS Vulnerability (AST-2016-008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a SDP offer denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If an SDP offer or answer is received with the Opus codec and
  with the format parameters separated using a space the code responsible for parsing will recursively
  call itself until it crashes. This occurs as the code does not properly handle spaces separating the
  parameters. This does NOT require the endpoint to have Opus configured in Asterisk. This also does
  not require the endpoint to be authenticated. If guest is enabled for chan_sip or anonymous in
  chan_pjsip an SDP offer or answer is still processed and the crash occurs.");

  script_tag(name:"impact", value:"An unauthenticated remote attacker may cause a denial of service
  condition.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.12.0 prior to 13.13.1 and 14.x prior
  to 14.2.1.");

  script_tag(name:"solution", value:"Update to version 13.13.1, 14.2.1 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-008.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94792");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^13\.") {
  if ( version_in_range(version: version, test_version: "13.12.0", test_version2: "13.13.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "13.13.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

if (version =~ "^14\.") {
  if (version_is_less(version: version, test_version: "14.2.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.2.1");
    security_message(port: port, data: report, proto: "udp");
    exit(0);
  }
}

exit(0);
