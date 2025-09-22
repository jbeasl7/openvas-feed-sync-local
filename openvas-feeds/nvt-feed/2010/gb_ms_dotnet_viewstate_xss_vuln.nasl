# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801344");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2088");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft .NET '__VIEWSTATE' Cross-Site Scripting vulnerability");
  script_xref(name:"URL", value:"https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt");
  script_xref(name:"URL", value:"http://www.blackhat.com/presentations/bh-dc-10/Byrne_David/BlackHat-DC-2010-Byrne-SGUI-slides.pdf");

  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/install", "aspNET/installed", "dotNET/version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct
  cross-site scripting attacks against the form control via the __VIEWSTATE parameter.");

  script_tag(name:"affected", value:"Microsoft .NET version 3.5 and prior.");

  script_tag(name:"insight", value:"The flaw is due to error in the handling of the '__VIEWSTATE'
  parameter in 'ASP.NET', which does not properly handle an unencrypted view state.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft .NET is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

dotNet = get_kb_item("dotNET/install");
if(!dotNet)
  exit(0);

apsdotNet = get_kb_item("aspNET/installed");
if(!aspdotNet)
  exit(0);

dotNet = get_kb_item("dotNET/version");
if(!dotNet)
  exit(0);

if(version_is_less_equal(version:dotNet, test_version:"3.5")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

