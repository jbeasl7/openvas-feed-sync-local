# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:moxa:miineport";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106468");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-12-13 08:40:04 +0700 (Tue, 13 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-23 19:25:00 +0000 (Thu, 23 Feb 2017)");

  script_cve_id("CVE-2016-9344", "CVE-2016-9346");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa MiiNePort Multiple Vulnerabilities (Dec 2016)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_moxa_miineport_consolidation.nasl");
  script_mandatory_keys("moxa/miineport/detected");

  script_tag(name:"summary", value:"Moxa MiiNePort is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-9344: Active session brute force

  - CVE-2016-9346: Cleartext storage of sensitive information");

  script_tag(name:"impact", value:"An attacker may be able to brute force an active session cookie
  to be able to download configuration files or read unencrypted sensitive data.");

  script_tag(name:"affected", value:"MiiNePort E1 versions prior to 1.8, MiiNePort E2 versions
  prior to 1.4 and MiiNePort E3 versions prior to 1.1.");

  script_tag(name:"solution", value:"Update the firmware to 1.8, 1.4 or 1.1 depending on the model.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-343-01");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=1214");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=263");
  script_xref(name:"URL", value:"http://www.moxa.com/support/download.aspx?type=support&id=2058");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (cpe =~ "^cpe:/o:moxa:miineport_e1") {
  if (version_is_less(version: version, test_version: "1.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.8");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:moxa:miineport_e2") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:moxa:miineport_e3") {
  if (version_is_less(version: version, test_version: "1.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
