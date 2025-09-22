# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:foxitsoftware:phantompdf";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810595");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2017-6883", "CVE-2017-8454", "CVE-2017-8455", "CVE-2017-8453");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-12 13:25:00 +0000 (Fri, 12 May 2017)");
  script_tag(name:"creation_date", value:"2017-04-05 18:47:49 +0530 (Wed, 05 Apr 2017)");
  script_name("Foxit PhantomPDF Multiple Vulnerabilities (May 2017) - Windows");

  script_tag(name:"summary", value:"Foxit PhantomPDF is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error within the parsing of TIFF images. The issue results from the lack
    of proper validation of user-supplied data which can result in a read past
    the end of an allocated object.

  - Multiple errors within the parsing of fonts in PDF files.The issue results
    from the lack of proper validation of user-supplied data, which can result
    in a read past the end of an allocated object.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (out-of-bounds read and application crash)
  via a crafted TIFF image. The vulnerability could lead to information disclosure.
  An attacker can leverage this in conjunction with other vulnerabilities to execute
  code in the context of the current process.");

  script_tag(name:"affected", value:"Foxit PhantomPDF version prior to 8.2.1 on
  windows");

  script_tag(name:"solution", value:"Upgrade to Foxit PhantomPDF version 8.2.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-133");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98319");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-134");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-135");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-140");
  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_foxit_phantom_reader_detect.nasl");
  script_mandatory_keys("foxit/phantompdf/ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!foxitVer = get_app_version(cpe:CPE, nofork:TRUE)){
  exit(0);
}

if(version_is_less_equal(version:foxitVer, test_version:"8.2.0.2192"))
{
  report = report_fixed_ver(installed_version:foxitVer, fixed_version:"8.2.1");
  security_message(data:report);
  exit(0);
}
