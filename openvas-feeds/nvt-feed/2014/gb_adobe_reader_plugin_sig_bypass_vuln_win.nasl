# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804624");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2002-0030");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-04 16:54:30 +0530 (Wed, 04 Jun 2014)");
  script_name("Adobe Reader Plugin Signature Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to plugin signature bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to fact the program only verifies the PE header of executable
code for a plug-in signature check.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to submit a modified plug-in to
bypass signature checks and execute malicious code on the system.");
  script_tag(name:"affected", value:"Adobe Reader 4.x and 5.x version on Windows.");
  script_tag(name:"solution", value:"Update to Adobe Reader version 6.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/11610");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7174");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/JSHA-5EZQGZ");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0148.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_old_adobe_reader_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader-Old/Ver");
  exit(0);
}

include("host_details.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^[4|5]\.")
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
