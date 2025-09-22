# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801109");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2510");
  script_name("Microsoft IE CA SSL Certificate Security Bypass Vulnerability (Oct 2009)");
  script_xref(name:"URL", value:"http://www.wired.com/threatlevel/2009/07/kaminsky/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36475");
  script_xref(name:"URL", value:"http://www.networkworld.com/news/2009/073009-more-holes-found-in-webs.html");
  script_xref(name:"URL", value:"http://www.networkworld.com/news/2009/091709-microsoft-ie-security-hole.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform man-in-the-middle
  attacks or impersonate trusted servers, which will aid in further attack.");

  script_tag(name:"affected", value:"Microsoft IE version 6.x/7.x/8.x.");

  script_tag(name:"insight", value:"Microsoft Internet Explorer fails to properly validate '\0' character in the
  domain name in a signed CA certificate, allowing attackers to substitute
  malicious SSL certificates for trusted ones.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a security bypass vulnerability.

  This VT has been deprecated and replaced by the VT 'Microsoft Windows CryptoAPI X.509 Spoofing Vulnerabilities (974571)' (OID: 1.3.6.1.4.1.25623.1.0.900876).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
