# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803035");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2010-3497");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-03 11:40:26 +0530 (Wed, 03 Oct 2012)");
  script_name("Symantec Norton AntiVirus Protocol Handler (HCP) Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://www.n00bz.net/antivirus-cve");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44188");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514356");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Oct/274");

  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Norton-AV/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow the attackers to bypass the
protection of AntiVirus technology and allows an attacker to drop and execute
known malicious files.");
  script_tag(name:"insight", value:"Symantec Norton AntiVirus fails to process 'hcp://' URLs by the
Microsoft Help and Support Center, which allows attackers to execute malicious
code via a protocol handler (hcp).");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Symantec Norton AntiVirus is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"affected", value:"Symantec Norton Antivirus 2011

NOTE: the researcher indicates that a vendor response was received, stating
that this issue 'falls into the work of our Firewall and not our AV
(per our methodology of layers of defense).'");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


navVer = get_kb_item("Symantec/Norton-AV/Ver");
if(!navVer){
  exit(0);
}
if(navVer =~ "^18"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
