# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108415");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5905", "CVE-2013-5906",
                "CVE-2013-5907", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376",
                "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0422",
                "CVE-2014-0423", "CVE-2014-0428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-01-22 10:20:04 +0530 (Wed, 22 Jan 2014)");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities-03 (Jan 2014) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exist.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to affect confidentiality,
  integrity and availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Java SE 7 update 45 and prior, Java SE 6 update 65 and prior, Java SE 5
  update 55 and prior on Linux.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56485");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64924");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64935");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64937");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64930");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(vers =~ "^1\.[5-7]") {
  if(version_in_range(version:vers, test_version:"1.7", test_version2:"1.7.0.45")||
     version_in_range(version:vers, test_version:"1.6", test_version2:"1.6.0.65")||
     version_in_range(version:vers, test_version:"1.5", test_version2:"1.5.0.55")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
