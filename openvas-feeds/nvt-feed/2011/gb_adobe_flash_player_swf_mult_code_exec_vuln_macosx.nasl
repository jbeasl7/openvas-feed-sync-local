# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802541");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2011-4694", "CVE-2011-4693");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-12-09 11:41:37 +0530 (Fri, 09 Dec 2011)");
  script_name("Adobe Flash Player 'SWF' File Multiple Code Execution Vulnerability - Mac OS X");
  script_xref(name:"URL", value:"http://partners.immunityinc.com/movies/VulnDisco-Flash0day-v2.mov");
  script_xref(name:"URL", value:"https://lists.immunityinc.com/pipermail/dailydave/2011-December/000402.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
arbitrary code in the context of the affected application.");
  script_tag(name:"affected", value:"Adobe Flash Player version 11.1.102.55 on Mac OS X.");
  script_tag(name:"insight", value:"The flaws are due to an unspecified error in the application,
allows remote attackers to execute arbitrary code via a crafted SWF file.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple arbitrary code execution vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(playerVer != NULL)
{
  if(version_is_equal(version:playerVer, test_version:"11.1.102.55")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
