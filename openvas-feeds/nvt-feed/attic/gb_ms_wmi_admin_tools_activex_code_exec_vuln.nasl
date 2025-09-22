# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801677");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_cve_id("CVE-2010-3973", "CVE-2010-4588");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft WMI Administrative Tools ActiveX Control RCE Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attackers execute arbitrary code
  and can compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft WMI Administrative Tools 1.1.");

  script_tag(name:"insight", value:"The flaws are due to the 'AddContextRef()' and 'ReleaseContext()'
  methods in the WMI Object Viewer Control using a value passed in the
  'lCtxHandle' parameter as an object pointer.");

  script_tag(name:"summary", value:"Microsoft WMI Administrative Tools is prone to multiple remote code execution
  (RCE) vulnerabilities.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.900281.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/725596");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45546");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3301");
  script_xref(name:"URL", value:"http://www.wooyun.org/bug.php?action=view&id=1006");

  exit(0);
}

exit(66);
