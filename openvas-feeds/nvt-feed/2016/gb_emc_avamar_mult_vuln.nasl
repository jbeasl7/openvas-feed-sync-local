# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emc:avamar";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106289");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-09-27 11:26:32 +0700 (Tue, 27 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)");

  script_cve_id("CVE-2016-0903", "CVE-2016-0904", "CVE-2016-0905", "CVE-2016-0920",
                "CVE-2016-0921");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Avamar < 7.3.0-233 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dell_avamar_consolidation.nasl");
  script_mandatory_keys("dell/avamar/detected");

  script_tag(name:"summary", value:"EMC Avamar is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-0903: Improper client side authentication

  - CVE-2016-0904: Improper encryption of communication channel

  - CVE-2016-0905: Privilege escalation via sudo

  - CVE-2016-0920: Command Injection in sudo script

  - CVE-2016-0921: Privilege escalation due to weak file permissions");

  script_tag(name:"impact", value:"An attacker may obtain root privileges, obtain sensitive
  client-server traffic information or read backup data.");

  script_tag(name:"affected", value:"EMC Avamar prior to version 7.3.0.");

  script_tag(name:"solution", value:"Update to version 7.3.0-233 or later.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2016/Sep/att-31/ESA-2016-065.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

s = split(version, sep: ".", keep: FALSE);

# 7.3.1.125 vs. 7.3.1
if (max_index(s) == 3)
  check = "7.3.0";
else if (max_index(s) == 4)
  check = "7.3.0.233";
else
  exit(0);

if (version_is_less(version: version, test_version: check)) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.0-233");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
