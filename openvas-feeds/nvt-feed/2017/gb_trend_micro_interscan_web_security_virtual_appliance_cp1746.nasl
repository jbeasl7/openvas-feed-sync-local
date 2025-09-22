# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trendmicro:interscan_web_security_virtual_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106708");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-03-31 09:02:03 +0700 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-6338", "CVE-2017-6339", "CVE-2017-6340");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trend Micro InterScan Web Security Virtual Appliance 6.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_trend_micro_interscan_web_security_virtual_appliance_consolidation.nasl");
  script_mandatory_keys("trendmicro/IWSVA/detected");

  script_tag(name:"summary", value:"Trend Micro has released a Critical Patch for Trend Micro InterScan Web
  Security Virtual Appliance (IWSVA) 6.5. This CP resolves multiple vulnerabilities in the product that could
  potentially allow a remote attacker to execute artibtrary code on vulnerable installations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Trend Micro InterScan Web Security Virtual Appliance (IWSVA) is prone to
  multiple vulnerabilities:

  - Command Injection Remote Command Execution (RCE)

  - Directory Traversal

  - Privilege Escalation

  - Authentication Bypass

  - Information Disclosure

  - Stored Cross-Site Scripting (XSS)");

  script_tag(name:"affected", value:"Version 6.5 before CP 1746 is known to be vulnerable.");

  script_tag(name:"solution", value:"Update to version 6.5 CP 1746 or newer.");

  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1116960");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (!build = get_kb_item("trendmicro/IWSVA/build"))
  exit(0);

if (version == "6.5" && int(build) < 1746) {
  report = report_fixed_ver(installed_version: version, installed_build: build,
                            fixed_version: "6.5", fixed_build: "1746");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
