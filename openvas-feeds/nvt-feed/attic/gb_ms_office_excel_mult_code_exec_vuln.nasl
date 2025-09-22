# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801595");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0978", "CVE-2011-0979");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Office Excel Axis and Art Object Parsing RCE Vulnerabilities");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Feb/86");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46225");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-042/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-041/");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.full-disclosure/77802");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code, can cause memory corruption and other attacks in the context of the
  application through crafted Excel file.");

  script_tag(name:"affected", value:"Microsoft Office Excel 2010.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in the usage of a specific field used for incrementing an array
  index. The application will copy the contents of the specified element into
  a statically sized buffer on the stack.

  - An error in parsing Office Art record, when parsing an office art object
  record, if an error occurs, the application will add a stray reference to an
  element which is part of a linked list. When receiving a window message,
  the application will proceed to navigate this linked list. This will
  access a method from the malformed object which can lead to code execution
  under the context of the application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Office Excel is prone to multiple remote code execution (RCE)
  vulnerabilities.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902410.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
