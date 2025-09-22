# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800408");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0021");
  script_name("NTP.org 'ntpd' EVP_VerifyFinal() Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499855");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2008-016.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause spoofing attacks via signature checks on DSA
  and ECDSA keys used with SSL/TLS.");

  script_tag(name:"affected", value:"NTPd version 4.2.4 through 4.2.4p5 and 4.2.5 through 4.2.5p150.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of return value in
  EVP_VerifyFinal function of openssl.");

  script_tag(name:"solution", value:"Update to version 4.2.4p6, 4.2.5p151 or later.");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to a security bypass vulnerability.");

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

if (((revcomp(a: version, b: "4.2.4") >= 0) && (revcomp(a: version, b: "4.2.4p5") <= 0)) ||
    ((revcomp(a: version, b: "4.2.5") >= 0) && (revcomp(a: version, b: "4.2.5p150") <= 0))) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4p6 or 4.2.5p151", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
