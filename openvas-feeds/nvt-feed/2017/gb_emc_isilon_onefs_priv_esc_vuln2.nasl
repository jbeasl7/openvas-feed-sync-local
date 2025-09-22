# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:emc_isilon_onefs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106889");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-21 11:18:56 +0700 (Wed, 21 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-4988");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Isilon OneFS Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_emc_isilon_onefs_consolidation.nasl");
  script_mandatory_keys("dell/emc_isilon/onefs/detected");

  script_tag(name:"summary", value:"EMC Isilon OneFS is affected by a privilege escalation vulnerability that
  could potentially be exploited by attackers to compromise the affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A cluster administrator, a compadmin user, or any user who has been given
  sudo privileges to run  isi_for_array commands could potentially exploit this vulnerability to gain root-level
  access to a cluster.");

  script_tag(name:"affected", value:"EMC Isilon OneFS 7.1.x, 7.2.0 - 7.2.1.4, 8.0.0 - 8.0.0.3, 8.0.1.0.");

  script_tag(name:"solution", value:"Update to version 7.2.1.5, 8.0.0.4, 8.0.1.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jun/41");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.1.0.0"))
  exit(99);

if (version_is_less(version: version, test_version: "7.2.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version == "8.0.1.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.1.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
