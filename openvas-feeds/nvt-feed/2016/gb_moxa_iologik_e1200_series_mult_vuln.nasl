# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:moxa:iologik_e12";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106360");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-10-31 13:26:41 +0700 (Mon, 31 Oct 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-19 19:06:00 +0000 (Wed, 19 May 2021)");

  script_cve_id("CVE-2016-8359", "CVE-2016-8372", "CVE-2016-8379", "CVE-2016-8350");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa ioLogik E1200 Series Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_iologik_devices_consolidation.nasl");
  script_mandatory_keys("moxa/iologik/detected");

  script_tag(name:"summary", value:"Moxa ioLogik E1200 Series are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Moxa ioLogik E1200 Series are prone to multiple vulnerabilities:

  - XSS: The web application fails to sanitize user input, which may allow an attacker to inject script or
    execute arbitrary code. (CVE-2016-8359)

  - Insufficiently protected credentials: A password is transmitted in a format that is not sufficiently secure.
    (CVE-2016-8372)

  - Weak password requirement: Users are restricted to using short passwords. (CVE-2016-8379)

  - CSRF: The web application may not sufficiently verify whether a request was provided by a valid user.
    (CVE-2016-8350)");

  script_tag(name:"impact", value:"An attacker who exploits these vulnerabilities may be able to remotely
  execute arbitrary code, modify parameters and settings, or reset the device.");

  script_tag(name:"affected", value:"Moxa ioLogik E1200 Series.");

  script_tag(name:"solution", value:"Update the Firmware.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-287-05");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:moxa:iologik_e12(10|12|14|41|42|60|62)") {
  if (version_is_less(version: version, test_version: "2.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.5");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:moxa:iologik_e12(11|40)") {
  if (version_is_less(version: version, test_version: "2.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:moxa:iologik_e1213") {
  if (version_is_less(version: version, test_version: "2.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.6");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
