# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dell:emc_isilon_onefs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106578");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-02-08 14:38:14 +0700 (Wed, 08 Feb 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-24 02:59:00 +0000 (Tue, 24 Jan 2017)");

  script_cve_id("CVE-2016-9870");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Isilon OneFS LDAP Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_emc_isilon_onefs_consolidation.nasl");
  script_mandatory_keys("dell/emc_isilon/onefs/detected");

  script_tag(name:"summary", value:"EMC Isilon OneFS is affected by an LDAP injection vulnerability that could
  potentially be exploited by a malicious user to compromise the system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A malicious high-privileged local user may leverage the LDAP injection
  vulnerability by injecting an asterisk into a username in LDAP searches, which may enable the attacker to
  impersonate other users on the system.");

  script_tag(name:"affected", value:"EMC Isilon OneFS 7.1.0.x, 7.1.1.0 - 7.1.1.10, 7.2.0.x, 7.2.1.0 - 7.2.1.2
  and 8.0.0.0.");

  script_tag(name:"solution", value:"Update to version 7.1.1.11, 7.2.1.3, 8.0.0.1 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2017/Jan/87");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "7.1.0.0"))
  exit(99);

if (version_is_less(version: version, test_version: "7.1.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.2.0.0", test_version2: "7.2.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.1.3");
  security_message(port: 0, data: report);
  exit(0);
}

if (version == "8.0.0.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
