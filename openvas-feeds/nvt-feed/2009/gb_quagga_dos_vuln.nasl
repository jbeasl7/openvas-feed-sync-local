# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800710");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1572");
  script_name("Quagga Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34817");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/05/01/2");
  script_xref(name:"URL", value:"https://marc.info/?l=quagga-dev&m=123364779626078&w=2");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_quagga_detect.nasl");
  script_mandatory_keys("Quagga/Ver");
  script_tag(name:"affected", value:"Quagga version 0.99.11 and prior.");
  script_tag(name:"insight", value:"This flaw is due to an assertion error in the BGP daemon while handling
  an AS path containing multiple 4 byte AS numbers.");
  script_tag(name:"summary", value:"Quagga for Linux is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution", value:"Apply the patch from the referenced mailinglist posting.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the daemon by advertising
  specially crafted AS paths and cause denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

quaggaVer = get_kb_item("Quagga/Ver");
if(!quaggaVer)
  exit(0);

if(version_is_less_equal(version:quaggaVer, test_version:"0.99.11")){
  report = report_fixed_ver(installed_version:quaggaVer, vulnerable_range:"Less than or equal to 0.99.11");
  security_message(port: 0, data: report);
}
