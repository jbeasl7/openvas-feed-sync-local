# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800461");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0255");
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (980088)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/980088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38055");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38056");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0291");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/980088.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain knowledge of
  sensitive information.");

  script_tag(name:"affected", value:"Internet Explorer Version 5.x, 6.x, 7.x and 8.x.");

  script_tag(name:"insight", value:"The issue is due to the browser failing to prevent local content from
  being rendered as HTML via the 'file://' protocol, which could allow attackers
  to access files with an already known filename and location on a vulnerable
  system.");

  script_tag(name:"summary", value:"Internet Explorer is prone to an information disclosure vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902191.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66);
