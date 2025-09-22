# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801830");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0346");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer 'ReleaseInterface()' RCE Vulnerability");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/427980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45639");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64482");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024940");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0026");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploits allows an attacker to run arbitrary code in the
  context of the user running the application. Failed attacks will cause
  denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8.0.7600.16385.");

  script_tag(name:"insight", value:"The flaw is caused by a use-after-free error within the 'mshtml.dll' library
  when handling circular references between JScript objects and Document Object
  Model (DOM) objects, which could allow remote attackers to execute arbitrary
  code via a specially crafted web page.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a remote code execution (RCE) vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.900278.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66);
