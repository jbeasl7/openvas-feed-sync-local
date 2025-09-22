# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810937");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 17:49:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-04-25 14:16:42 +0530 (Tue, 25 Apr 2017)");
  script_name("Symantec Endpoint Protection Small Business Edition RAR File Parser DoS Vulnerabilities");

  script_tag(name:"summary", value:"Symantec Endpoint Protection Small Business Edition is prone to denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to mishandling of
  RAR file by RAR file parser component in the AntiVirus Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (out-of-bounds read) via a crafted RAR
  file that is mishandled during decompression.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection Small Business
  Edition 12.1.");

  script_tag(name:"solution", value:"Upgrade to SEP SBE (Hosted) or Symantec Endpoint
  Protection Enterprise Edition (EE) 12.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40405");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92868");
  script_xref(name:"URL", value:"https://support.symantec.com/en_US/article.TECH235368.html");
  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20160919_00");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/SEP/SmallBusiness");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:sepVer, test_version:"12.1"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"Upgrade to SEP SBE (Hosted) or SEP (EE) 12.1");
  security_message(data:report);
  exit(0);
}
exit(0);
