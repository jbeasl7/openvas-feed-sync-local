# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900623");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0159");
  script_name("NTP.org 'ntpd' Stack Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34608");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34481");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49838");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0999");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code or to cause the application to crash.");

  script_tag(name:"affected", value:"NTPd version prior to 4.2.4p7-RC2.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the cookedprint()
  function in ntpq/ntpq.c while processing malicious response from
  a specially crafted remote time server.");

  script_tag(name:"solution", value:"Update to version 4.2.4p7-RC2 or later.");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to multiple stack buffer overflow vulnerabilities.");

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

if (revcomp(a: version, b: "4.2.4p7-rc2") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4p7-RC2", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
