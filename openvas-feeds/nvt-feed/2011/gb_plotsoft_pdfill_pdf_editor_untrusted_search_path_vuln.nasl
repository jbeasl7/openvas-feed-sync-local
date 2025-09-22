# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802177");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-3690");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("PlotSoft PDFill PDF Editor Untrusted Search Path Vulnerability");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2011-3690");
  script_xref(name:"URL", value:"http://olex.openlogic.com/wazi/2011/pdfill-pdf-editor-8-0-medium/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_plotsoft_pdfill_pdf_editor_detect.nasl");
  script_mandatory_keys("PlotSoft/PDFill/PDF/Editor/Ver");
  script_tag(name:"insight", value:"The flaw is due to untrusted search path vulnerability, which
allows local users to gain privileges.");
  script_tag(name:"solution", value:"Upgrade to version 9.0 or later.");
  script_tag(name:"summary", value:"PlotSoft PDFill PDF Editor is prone to untrusted search path vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow local users to gain privileges
via a Trojan horse mfc70enu.dll or mfc80loc.dll in the current working directory.");
  script_tag(name:"affected", value:"PlotSoft PDFill PDF Editor version 8.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.pdfill.com/download.html");
  exit(0);
}


include("version_func.inc");

pdfVer = get_kb_item("PlotSoft/PDFill/PDF/Editor/Ver");
if(!pdfVer){
  exit(0);
}

if(version_is_equal(version:pdfVer, test_version:"8.0")){
  report = report_fixed_ver(installed_version:pdfVer, vulnerable_range:"Equal to 8.0");
  security_message(port: 0, data: report);
}
