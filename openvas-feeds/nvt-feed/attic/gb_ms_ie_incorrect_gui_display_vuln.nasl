# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801831");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0347");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer Incorrect GUI Display Vulnerability");
  script_xref(name:"URL", value:"http://lcamtuf.coredump.cx/cross_fuzz/msie_display.jpg");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2490606.mspx");
  script_xref(name:"URL", value:"http://lcamtuf.blogspot.com/2011/01/announcing-crossfuzz-potential-0-day-in.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploits will allow an attacker to trigger an
  incorrect GUI display and have unspecified other impact.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer on Microsoft Windows XP.");

  script_tag(name:"insight", value:"The flaw is caused due an error which allows remote attackers to
  trigger an incorrect GUI display and have unspecified other impact via vectors
  related to the DOM implementation.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has installed with Internet Explorer and is prone to
  incorrect GUI display vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902334.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
