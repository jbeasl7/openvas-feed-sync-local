# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900724");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1808");
  script_name("Windows XP 'SPI_GETDESKWALLPAPER' DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35120");
  script_xref(name:"URL", value:"http://www.ragestorm.net/blogs/?p=78");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute the malicious code
  into the context of an affected operating system and cause crash in the
  operating system.");

  script_tag(name:"affected", value:"Microsoft Windows XP SP3 and prior.");

  script_tag(name:"insight", value:"Error exists while making an 'SPI_SETDESKWALLPAPER' SystemParametersInfo
  call with an improperly terminated 'pvParam' argument, followed by an
  'SPI_GETDESKWALLPAPER' SystemParametersInfo system calls.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"Windows XP operating system is prone to a denial of service (DoS) vulnerability.

  This VT has been superseded by OID:1.3.6.1.4.1.25623.1.0.900669.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
