# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810221");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-7871", "CVE-2015-7855", "CVE-2015-7854", "CVE-2015-7853", "CVE-2015-7852",
                "CVE-2015-7851", "CVE-2015-7850", "CVE-2015-7849", "CVE-2015-7848", "CVE-2015-7701",
                "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7691", "CVE-2015-7692",
                "CVE-2015-7702");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 12:15:00 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2016-11-29 12:32:57 +0530 (Tue, 29 Nov 2016)");
  script_name("NTP.org 'ntpd' 'decodenetnum' And 'loop counter underrun' DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40840");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77283");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77275");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug2913");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#October_2015_NTP_4_2_8p4_Securit");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors are due to:

  - CVE-2015-7871 NAK to the Future: Symmetric association authentication bypass via crypto-NAK

  - CVE-2015-7855 decodenetnum() will ASSERT botch instead of returning FAIL on some bogus values

  - CVE-2015-7854 Password Length Memory Corruption Vulnerability

  - CVE-2015-7853 Invalid length data provided by a custom refclock driver could cause a buffer overflow

  - CVE-2015-7852 ntpq atoascii() Memory Corruption Vulnerability

  - CVE-2015-7851 saveconfig Directory Traversal Vulnerability

  - CVE-2015-7850 remote config logfile-keyfile

  - CVE-2015-7849 trusted key use-after-free

  - CVE-2015-7848 mode 7 loop counter underrun

  - CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC

  - CVE-2015-7703 configuration directives 'pidfile' and 'driftfile' should only be allowed locally

  - CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD should validate the origin timestamp field

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete autokey data packet length checks");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"NTPd version 4.x prior to 4.2.8p4 and 4.3.0 prior to 4.3.77.");

  script_tag(name:"solution", value:"Update to version 4.2.8p4, 4.3.77 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if (version =~ "^4\.[0-2]") {
  if (revcomp(a: version, b: "4.2.8p4") < 0) {
    VULN = TRUE;
    fix = "4.2.8p4";
  }
}

else if (version =~ "^4\.3") {
  if (revcomp(a: version, b: "4.3.77") < 0) {
    VULN = TRUE;
    fix = "4.3.77";
  }
}

if (VULN) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
