# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800107");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2008-2641");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-04 09:54:24 +0200 (Sat, 04 Oct 2008)");
  script_xref(name:"CB-A", value:"08-0105");
  script_name("Adobe Reader/Acrobat JavaScript Method Handling Vulnerability (APSB08-15) - Linux");

  script_tag(name:"summary", value:"Adobe Reader/Acrobat is prone to a remote code execution (RCE)
  vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error in a JavaScript method, which
could allow attackers to execute arbitrary code by tricking a user into opening
a specially crafted PDF document.");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code or
an attacker could take complete control of an affected system or cause a
denial of service condition.");
  script_tag(name:"affected", value:"Adobe Reader version 7.0.9 and prior

  Adobe Reader versions 8.0 through 8.1.2");
  script_tag(name:"solution", value:"Apply the security update from the referenced advisory.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/43307");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29908");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/1906/products");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb08-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!adobeVer = get_app_version(cpe:CPE))
  exit(0);

# Security Update 1 (SU1) is applied
if(adobeVer =~ "^8.1.2_SU[0-9]+")
  exit(99);

if(version_is_less_equal(version:adobeVer, test_version:"7.0.9") ||
   version_in_range(version:adobeVer, test_version:"8.0", test_version2:"8.1.2")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
