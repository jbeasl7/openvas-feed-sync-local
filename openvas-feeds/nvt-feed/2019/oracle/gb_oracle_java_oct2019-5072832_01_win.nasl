# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815638");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2019-2949", "CVE-2019-2989", "CVE-2019-2958", "CVE-2019-2999",
                "CVE-2019-2962", "CVE-2019-2988", "CVE-2019-2992", "CVE-2019-2964",
                "CVE-2019-2973", "CVE-2019-2981", "CVE-2019-2978", "CVE-2019-2894",
                "CVE-2019-2983", "CVE-2019-2933", "CVE-2019-2945");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2019-10-16 10:31:47 +0530 (Wed, 16 Oct 2019)");
  script_name("Oracle Java SE Security Updates (oct2019-5072832) 01 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors in
  'Kerberos', 'Networking', 'Libraries', 'Javadoc', '2D', 'Concurrency', 'JAXP',
  'Security' and 'Serialization' components.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attacker to have an impact on confidentiality, integrity and
  availability.");

  script_tag(name:"affected", value:"Oracle Java SE version 7u231(1.7.0.231) and
  earlier, 8u221(1.8.0.221) and earlier, 11.0.4 and earlier, 13 on Windows.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JDK_or_JRE/Win/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.231")||
   version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.221")||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.4")||
   version_is_equal(version:vers, test_version:"13.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
