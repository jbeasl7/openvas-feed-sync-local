# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108397");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2015-0491", "CVE-2015-0488", "CVE-2015-0480", "CVE-2015-0478",
                "CVE-2015-0477", "CVE-2015-0469", "CVE-2015-0460", "CVE-2015-0459");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-04-21 16:34:06 +0530 (Tue, 21 Apr 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 (Apr 2015) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the Java Cryptography Extension (JCE) subcomponent's RSA signature
  implementation.

  - An error in the JSSE subcomponent that is triggered when checking X.509
  certificate options.

  - An error in the 'ReferenceProcessor::process_discovered_references' function
  in share/vm/memory/referenceProcessor.cpp script.

  - Two unspecified errors related to the 2D subcomponent.

  - An error in the Beans subcomponent related to permissions and resource
  loading.

  - An off-by-one overflow condition in the functions
  'LigatureSubstitutionProcessor::processStateEntry' and
  'LigatureSubstitutionProcessor2::processStateEntry' within LigatureSubstProc.cpp
  and LigatureSubstProc2.cpp scripts respectively.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain knowledge of potentially sensitive information, conduct
  denial-of-service attacks, execute arbitrary code and other unspecified impact.");

  script_tag(name:"affected", value:"Oracle Java SE 5.0 update 81 and prior,
  6 update 91 and prior, 7 update 76 and prior, and 8 update 40 and prior on
  Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74111");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74119");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74072");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74097");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74083");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun/Java/JRE/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk", "cpe:/a:sun:jre", "cpe:/a:sun:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[5-8]") {
  if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.40")||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.76")||
     version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.91")||
     version_in_range(version:vers, test_version:"1.5.0", test_version2:"1.5.0.81")) {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + "Apply the patch"  + '\n';
    security_message(data:report);
    exit(0);
  }
}

exit(99);
