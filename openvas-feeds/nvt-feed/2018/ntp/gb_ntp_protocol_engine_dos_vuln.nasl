# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812792");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2018-7185");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-03-07 12:09:28 +0530 (Wed, 07 Mar 2018)");
  script_name("NTP.org 'ntpd' 'protocol engine' Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3454");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a bug that was
  inadvertently introduced into the 'protocol engine' that allows a non-authenticated
  zero-origin (reset) packet to reset an authenticated interleaved peer association.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service condition, denying service to legitimate
  users.");

  script_tag(name:"affected", value:"NTPd version 4.2.6 through 4.2.8p10.");

  script_tag(name:"solution", value:"Update to version 4.2.8p11 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (version =~ "^4\.2") {
  if ((revcomp(a: version, b: "4.2.6") >= 0) && (revcomp(a: version, b: "4.2.8p11") < 0)) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p11", install_path: location);
    security_message(port: port, proto: proto, data: report);
    exit(0);
  }
}

exit(99);
