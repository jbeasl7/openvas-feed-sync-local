# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:aloha:aloahapdfviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804312");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-4978");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-13 11:02:14 +0530 (Thu, 13 Feb 2014)");
  script_name("Aloaha PDF Viewer Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Aloaha PDF Viewer is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to some unspecified error when processing PDF files.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service or execution of arbitrary code.");
  script_tag(name:"affected", value:"Aloaha PDF Viewer version 5.0.0.7 and probably other versions.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54585");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62036");
  script_xref(name:"URL", value:"http://www.coresecurity.com/advisories/aloaha-pdf-suite-buffer-overflow-vulnerability");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_aloaha_pdf_viewer_detect.nasl");
  script_mandatory_keys("Aloaha/PDF/Viewer");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!pdfVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:pdfVer, test_version:"5.0.0.7"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
