# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142857");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2019-09-06 05:05:08 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-10 16:49:00 +0000 (Tue, 10 Sep 2019)");

  script_cve_id("CVE-2019-15639");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Audio Transcoding DoS Vulnerability (AST-2019-005)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service vulnerability in audio
  transcoding.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This issue presented itself when an RTP packet containing no
  audio (and thus no samples) was received. In a particular transcoding scenario this audio frame
  would get turned into a frame with no origin information. If this new frame was then given to the
  audio transcoding support a crash would occur as no samples and no origin information would be
  present. The transcoding scenario requires the 'genericplc' option to be set to enabled (the
  default) and a transcoding path from the source format into signed linear and then from signed
  linear into another format.");

  script_tag(name:"affected", value:"Asterisk Open Source 13.28.0 and 16.5.0.");

  script_tag(name:"solution", value:"Update to version 13.28.1, 16.5.1 or later.");

  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2019-005.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if ("cert" >< version)
  exit(99);

if (version =~ "^13\.28\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.28.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

if (version =~ "^16\.5\.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.5.1");
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(0);
