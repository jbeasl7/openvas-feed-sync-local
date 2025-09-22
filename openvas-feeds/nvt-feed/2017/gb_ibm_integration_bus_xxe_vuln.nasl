# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:integration_bus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810802");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2016-9706");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-07 02:59:00 +0000 (Tue, 07 Mar 2017)");
  script_tag(name:"creation_date", value:"2017-03-13 16:01:06 +0530 (Mon, 13 Mar 2017)");
  script_name("IBM Integration Bus XXE Vulnerability (290615)");

  script_tag(name:"summary", value:"IBM Integration Bus is prone to an XML External Entity (XXE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an XML External Entity
  Injection (XXE) error when processing XML data.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to expose highly sensitive information or consume all available memory resources.");

  script_tag(name:"affected", value:"IBM Integration Bus 9.0 through 9.0.0.5
  and 10.0 through 10.0.0.4");

  script_tag(name:"solution", value:"Upgrade to IBM Integration Bus 9.0.0.6
  or 10.0.0.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-ibm-integration-bus-and-websphere-message-broker-soap-flows-are-vulnerable-xml-external-entity-attack-cve-2016-9706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96274");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/ibm-integration-bus-v90-fix-pack-9006");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/ibm-integration-bus-v100-fix-pack-10005");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_integration_bus_detect.nasl");
  script_mandatory_keys("IBM/Integration/Bus/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ibVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(ibVer =~ "^9\.0")
{
  if(version_in_range(version:ibVer, test_version:"9.0.0.0", test_version2:"9.0.0.5"))
  {
    fix = "9.0.0.6";
    VULN = TRUE;
  }
}

else if(ibVer =~ "^10\.0")
{
  if(version_in_range(version:ibVer, test_version:"10.0.0.0", test_version2:"10.0.0.4"))
  {
    fix = "10.0.0.5";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:ibVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
