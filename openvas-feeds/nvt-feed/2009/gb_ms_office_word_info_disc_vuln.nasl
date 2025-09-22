# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800343");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-6063");
  script_name("Microsoft Word 2007 Sensitive Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/486088/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Word/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to retrieve sensitive
  information about sender's account name and a Temporary Internet Files
  subdirectory name.");

  script_tag(name:"affected", value:"Microsoft Office Word 2007.");

  script_tag(name:"insight", value:"In MS Word when the Save as PDF add-on is enabled, places an absolute pathname
  in the Subject field during an Email as PDF operation.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Word is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^12\.")
{
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer || wordVer !~ "^12\."){
    exit(0);
  }

  if(version_in_range(version:wordVer, test_version:"12.0", test_version2:"12.0.6331.4999")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
