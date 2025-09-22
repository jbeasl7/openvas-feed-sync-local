# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807551");
  script_version("2024-07-01T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-0695", "CVE-2016-0687", "CVE-2016-0686", "CVE-2016-3443",
                "CVE-2016-3427", "CVE-2016-3425", "CVE-2016-3422", "CVE-2016-3449");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-01 05:05:39 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:19 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-04-22 10:41:22 +0530 (Fri, 22 Apr 2016)");
  script_name("Oracle Java SE Multiple Vulnerabilities (Apr 2016) - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Security component in 'OpenJDK' failed to check the digest algorithm
    strength when generating DSA signatures.

  - The JAXP component in 'OpenJDK' failed to properly handle Unicode surrogate
    pairs used as part of the XML attribute values.

  - The RMI server implementation in the JMX component in 'OpenJDK' did not
    restrict which classes can be deserialized when deserializing authentication
    credentials.

  - Multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity and availability via different
  vectors.");

  script_tag(name:"affected", value:"Oracle Java SE 6 update 113 and prior,
  7 update 99 and prior and 8 update 77 and prior on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]") {
  if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.113") ||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.99") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.77")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
