# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802379");
  script_tag(name:"creation_date", value:"2012-01-13 16:00:36 +0100 (Fri, 13 Jan 2012)");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2011-5046");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Kernel 'win32k.sys' Memory Corruption Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51122");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18275/");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code on the system with kernel-level privileges.");

  script_tag(name:"affected", value:"Microsoft Windows 7 Professional 64-bit.");

  script_tag(name:"insight", value:"The flaw is due to an error in win32k.sys, when handling a
  specially crafted web page containing an IFRAME with an overly large 'height'
  attribute viewed using the Apple Safari browser.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Windows 7 Professional 64-bit is prone to a memory
  corruption vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902810.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
