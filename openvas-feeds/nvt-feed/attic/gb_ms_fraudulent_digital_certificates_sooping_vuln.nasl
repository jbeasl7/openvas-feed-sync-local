# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902403");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Windows Fraudulent Digital Certificates Spoofing Vulnerability");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2524375.mspx");
  script_xref(name:"URL", value:"http://forums.cnet.com/7723-6132_102-521672.html?messageId=5105699");
  script_xref(name:"URL", value:"http://vulnerabilityteam.blogspot.com/2011/03/fraudulent-ssl-certificates.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks, or perform man-in-the-middle attacks against all Web browser
  users including users of Internet Explorer.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows 2K3 Service Pack 2 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is caused by an error related to the use of several revoked and
  fraudulent SSL certificates for public web sites, which could allow attackers
  to decrypt SSL traffic sent to legitimate web sites by manipulating the DNS
  servers and using the fraudulent certificates.");

  script_tag(name:"solution", value:"Apply the patch from the referenced link.");

  script_tag(name:"summary", value:"Microsoft Windows operating system is prone to a spoofing vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.801953.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2524375");
  exit(0);
}


exit(66);
