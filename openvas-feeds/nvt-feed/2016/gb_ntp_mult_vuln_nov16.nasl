# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106404");
  script_version("2024-02-23T14:36:45+0000");
  script_cve_id("CVE-2016-9311", "CVE-2016-9310", "CVE-2016-7427", "CVE-2016-7428", "CVE-2016-9312",
                "CVE-2016-7431", "CVE-2016-7434", "CVE-2016-7429", "CVE-2016-7426", "CVE-2016-7433");
  script_tag(name:"last_modification", value:"2024-02-23 14:36:45 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-03 11:18:33 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-24 11:29:00 +0000 (Thu, 24 Jan 2019)");
  script_name("NTP.org 'ntpd' 4.0.90 - 4.2.8p8, 4.3.0 - 4.3.93 Multiple Vulnerabilities (Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/633847");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd, is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"NTP.org's ntpd is prone to multiple vulnerabilities:

  - An exploitable configuration modification vulnerability exists in the control mode (mode 6) functionality of
  ntpd. If, against long-standing BCP recommendations, 'restrict default noquery ...' is not specified, a
  specially crafted control mode packet can set ntpd traps, providing information disclosure and DDoS
  amplification, and unset ntpd traps, disabling legitimate monitoring. (CVE-2016-9310)

  - ntpd does not enable trap service by default. If trap service has been explicitly enabled, an attacker can
  send a specially crafted packet to cause a null pointer dereference that will crash ntpd, resulting in a denial
  of service. (CVE-2016-9311)");

  script_tag(name:"impact", value:"A remote unauthenticated attacker may be able to perform a denial of
  service on NTP.org's ntpd.");

  script_tag(name:"affected", value:"NTPd version 4.0.90 up to 4.2.8p8, 4.3.0 up to 4.3.93.");

  script_tag(name:"solution", value:"Update to version 4.2.8p9, 4.3.94 or later.");

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

if ((revcomp(a: version, b: "4.0.90") >= 0) && (revcomp(a: version, b: "4.2.8p9") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p9", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

if ((revcomp(a: version, b: "4.3.0") >= 0) && (revcomp(a: version, b: "4.3.94") < 0)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.94", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
