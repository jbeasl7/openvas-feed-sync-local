# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:meinbergglobal:lantime_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106110");
  script_version("2025-07-17T05:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-17 05:43:33 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-06-24 16:45:17 +0700 (Fri, 24 Jun 2016)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-03 01:29:00 +0000 (Sun, 03 Sep 2017)");

  script_cve_id("CVE-2016-3962", "CVE-2016-3988", "CVE-2016-3989", "CVE-2016-4953",
                "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Meinberg LANTIME < 6.20.005 Multiple Vulnerabilities (MBGSA-1604)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_meinberg_lantime_consolidation.nasl");
  script_mandatory_keys("meinberg/lantime/detected");

  script_tag(name:"summary", value:"Meinberg LANTIME NTP Timeserver devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-3962: Remote stack buffer overflow vulnerability involving parsing of parameter in POST
  request in function provides privilege of web server 'nobody'.

  - CVE-2016-3988: Remote stack buffer overflow vulnerability is present while parsing nine
  different parameters in POST request in function.

  - CVE-2016-3989: Weak access controls allow for privilege escalation from 'nobody' to 'root' user.
  'nobody' has permissions to alter script that can only run as 'root'.

  - CVE-2016-4953, CVE-2016-4954, CVE-2016-4955, CVE-2016-4956, CVE-2016-4957: Multiple
  vulnerabilities in NTP.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could cause a
  buffer overflow condition that may allow escalation to root privileges.");

  script_tag(name:"affected", value:"Meinberg LANTIME devices with firmware versions prior to
  6.20.005.");

  script_tag(name:"solution", value:"Update to firmware version 6.20.005 or later.");

  script_xref(name:"URL", value:"https://www.meinbergglobal.com/english/news/meinberg-security-advisory-mbgsa-1604-webui-and-ntp.htm");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-175-03");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/321640");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "6.20.005")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.20.005");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
