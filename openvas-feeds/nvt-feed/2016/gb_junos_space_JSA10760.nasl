# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:juniper:junos_space";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106348");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-10-13 09:18:34 +0700 (Thu, 13 Oct 2016)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:24:00 +0000 (Wed, 22 Mar 2017)");

  script_cve_id("CVE-2016-4926", "CVE-2016-4927", "CVE-2016-4928", "CVE-2016-4929",
                "CVE-2016-4930", "CVE-2016-4931");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Juniper Networks Junos Space Multiple Vulnerabilities (JSA10760)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_space_consolidation.nasl");
  script_mandatory_keys("juniper/junos/space/detected");

  script_tag(name:"summary", value:"Juniper Networks Junos Space is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-4926: Insufficient authentication vulnerability in Junos Space may allow remote
  network based users with access to Junos Space web interface to perform certain administrative
  tasks without authentication.

  - CVE-2016-4927: Insufficient validation of SSH keys in Junos Space may allow man-in-the-middle
  (MITM) type of attacks while a Space device is communicating with managed devices.

  - CVE-2016-4928: Cross site request forgery vulnerability in Junos Space may allow remote
  attackers to perform certain administrative actions on Junos Space.

  - CVE-2016-4929: Command injection vulnerability in Junos Space may allow unprivileged users to
  execute code as root user on the device.

  - CVE-2016-4930: Cross site scripting vulnerability may allow remote attackers to steal sensitive
  information or perform certain administrative actions on Junos Space.

  - CVE-2016-4931: XML entity injection vulnerability may allow unprivileged users to cause a
  denial of service condition.");

  script_tag(name:"affected", value:"Juniper Networks Junos Space versions prior to 15.2R2.");

  script_tag(name:"solution", value:"Update to version 15.2R2 or later.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10760");

  exit(0);
}

include("host_details.inc");
include("junos.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

version = toupper(version);

if (check_js_version(ver: version, fix: "15.2R2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.2R2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
