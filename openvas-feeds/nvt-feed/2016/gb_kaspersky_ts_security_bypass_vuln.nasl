# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kaspersky:total_security_2015";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806854");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-8579");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-02-04 10:20:32 +0530 (Thu, 04 Feb 2016)");
  script_name("Kaspersky Total Security Security Bypass Vulnerability");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_kaspersky_total_security_detect.nasl");
  script_mandatory_keys("Kaspersky/TotalSecurity/Ver");

  script_xref(name:"URL", value:"http://blog.ensilo.com/the-av-vulnerability-that-bypasses-mitigations");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78815");
  script_xref(name:"URL", value:"http://usa.kaspersky.com/downloads/");

  script_tag(name:"summary", value:"Kaspersky Total security is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the allocation of memory with Read, Write, Execute (RWX)
  permissions at predictable addresses when protecting user-mode processes.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote
  attackers to bypass the DEP and ASLR protection mechanisms via unspecified vectors.");

  script_tag(name:"affected", value:"Kaspersky Total Security version 15.0.2.361. Other versions might be affected as well.");

  script_tag(name:"solution", value:"Upgrade to latest version of Kaspersky Total
  Security from the referenced vendor link.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!kasVer = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:kasVer, test_version:"15.0.2.361")) {
  report = report_fixed_ver(installed_version:kasVer, fixed_version:"See the references");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);