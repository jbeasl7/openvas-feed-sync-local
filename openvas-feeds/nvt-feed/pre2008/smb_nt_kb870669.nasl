# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12298");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("ADODB.Stream object from Internet Explorer (KB870669)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"An ADO stream object represents a file in memory. The stream object contains
  several methods for reading and writing binary files and text files.

  When this by-design functionality is combined with known security
  vulnerabilities in Microsoft Internet Explorer, an Internet Web site could
  execute script from the Local Machine zone.");

  script_tag(name:"insight", value:"This behavior occurs because the ADODB.Stream object permits
  access to the hard disk when the ADODB.Stream object is hosted in Internet Explorer.");

  script_tag(name:"solution", value:"The vendor has released updates, please see the references for more information.");

  script_xref(name:"URL", value:"https://www.microsoft.com/de-de/download/details.aspx?id=4782");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10514");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags");

if ( value && value != 1024 && hotfix_missing(name:"870669") )
  security_message(port:0);
