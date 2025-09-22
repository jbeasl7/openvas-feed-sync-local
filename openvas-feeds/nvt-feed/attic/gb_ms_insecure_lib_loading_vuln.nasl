# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802136");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_cve_id("CVE-2010-3337");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Insecure Library Loading Vulnerability (2269637)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2264107");
  script_xref(name:"URL", value:"http://forums.cnet.com/7723-6132_102-407460.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2269637.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to remotely execute arbitrary
  code in the context of the user running the vulnerable application when the
  user opens a file from an untrusted location.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2003 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to the applications installed on windows, passes an
  insufficiently qualified path of '.dll' files when loading an external library.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Security Advisory (2269637).

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902792.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
