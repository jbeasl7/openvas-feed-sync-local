# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812037");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2017-10388", "CVE-2017-10293", "CVE-2017-10346", "CVE-2017-10345",
                "CVE-2017-10285", "CVE-2017-10356", "CVE-2017-10348", "CVE-2017-10295",
                "CVE-2017-10349", "CVE-2017-10347", "CVE-2017-10274", "CVE-2017-10355",
                "CVE-2017-10357", "CVE-2017-10281");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-30 03:36:00 +0000 (Sat, 30 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-10-18 13:03:18 +0530 (Wed, 18 Oct 2017)");
  script_name("Oracle Java SE Security Updates (oct2017-3236626) 02 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to flaws in the
  'Hotspot', 'RMI ', 'Libraries', 'Smart Card IO', 'Security', 'Javadoc', 'JAXP',
  'Serialization' and 'Networking' components of the application.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to gain elevated privileges, partially access and
  partially modify data, access sensitive data, obtain sensitive information or
  cause a denial of service.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0.161 and earlier,
  1.7.0.151 and earlier, 1.8.0.144 and earlier, 9.0 on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101321");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101319");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101384");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101348");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101333");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101369");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101355");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101378");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^(1\.[6-8]|9)\.") {
  if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.161") ||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.151") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.144") ||
     vers == "9.0") {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}

exit(0);
