# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810678");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2017-6464", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6455",
                "CVE-2017-6452", "CVE-2017-6459", "CVE-2017-6458", "CVE-2017-6451",
                "CVE-2017-6460", "CVE-2016-9042");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 01:29:00 +0000 (Tue, 24 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-03-23 11:35:22 +0530 (Thu, 23 Mar 2017)");
  script_name("NTP.org 'ntpd' Multiple Denial-of-Service Vulnerabilities (Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3389");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3388");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3387");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3386");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3385");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3384");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3383");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3382");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3381");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3380");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3379");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3378");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3377");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3376");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3361");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Improper handling of a malformed mode configuration directive.

  - A buffer overflow error in Legacy Datum Programmable Time Server refclock
  driver.

  - Improper handling of an invalid setting via the :config directive.

  - Incorrect pointer usage in the function 'ntpq_stripquotes'.

  - No allocation of memory for a specific amount of items of the same size in
  'oreallocarray' function.

  - ntpd configured to use the PPSAPI under Windows.

  - Limited passed application path size under Windows.

  - An error leading to garbage registry creation in Windows.

  - Copious amounts of Unused Code.

  - Off-by-one error in Oncore GPS Receiver.

  - Potential Overflows in 'ctl_put' functions.

  - Improper use of 'snprintf' function in mx4200_send function.

  - Buffer Overflow in ntpq when fetching reslist from a malicious ntpd.

  - Potential Overflows in 'ctl_put' functions.

  - Potential denial of service in origin timestamp check functionality of ntpd.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service condition.");

  script_tag(name:"affected", value:"NTPd version 4.x prior to 4.2.8p10 and 4.3.x prior to
  4.3.94.");

  script_tag(name:"solution", value:"Update to version 4.2.8p10, 4.3.94 or later.");

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

if (version =~ "^4\.[0-2]") {
  if (revcomp(a: version, b: "4.2.8p10") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p10", install_path: location);
    security_message(port: port, proto: proto, data: report);
    exit(0);
  }
}

else if (version =~ "^4\.3") {
  if (revcomp(a: version, b: "4.3.94") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.94", install_path: location);
    security_message(port: port, proto: proto, data: report);
    exit(0);
  }
}

exit(99);
