# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801594");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0976");
  script_name("Microsoft PowerPoint 2007 OfficeArt Atom RCE Vulnerability");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-044/");
  script_xref(name:"URL", value:"http://dvlabs.tippingpoint.com/blog/2011/02/07/zdi-disclosure-microsoft");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  codes, can cause memory corruption and other attacks in the context of the
  application through a crafted Power Point file.");

  script_tag(name:"affected", value:"MS PowerPoint 2007 Service Pack 2.");

  script_tag(name:"insight", value:"The flaw exists with the way application will parse external
  objects within an Office Art container. When parsing this object, the
  application will append an uninitialized object to a list. When destroying this
  object during document close (WM_DESTROY), the application will access a method
  that does not exist.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Office Power Point is prone to a remote code execution (RCE)
  vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902411.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
