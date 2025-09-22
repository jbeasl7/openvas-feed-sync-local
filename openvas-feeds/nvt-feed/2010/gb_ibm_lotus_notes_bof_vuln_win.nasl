# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801327");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1608");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IBM Lotus Notes Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38622");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38300");
  script_xref(name:"URL", value:"https://forum.immunityinc.com/board/thread/1161/vulndisco-9-0/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_mandatory_keys("IBM/LotusNotes/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code in the context of the user running the application. Failed exploit attempts
will result in a denial-of-service condition.");
  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.0 and 8.5 to 8.5 FP1 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error in application, which fails
to adequately  perform boundary checks on user supplied data and can be exploited
to cause a stack based buffer overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"IBM Lotus Notes is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(lotusVer != NULL)
{
  if(version_is_equal(version:lotusVer, test_version:"8.0") ||
     version_in_range(version:lotusVer, test_version:"8.5", test_version2:"8.5.1.9167")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
