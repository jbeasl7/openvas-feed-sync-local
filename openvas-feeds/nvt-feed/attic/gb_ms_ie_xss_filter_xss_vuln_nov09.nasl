# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900898");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4074");
  script_name("Microsoft Internet Explorer 'XSS Filter' XSS Vulnerabilities (Nov 2009)");
  script_xref(name:"URL", value:"http://www.owasp.org/images/5/50/OWASP-Italy_Day_IV_Maone.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37135");
  script_xref(name:"URL", value:"http://www.theregister.co.uk/2009/11/20/internet_explorer_security_flaw/");
  script_xref(name:"URL", value:"http://hackademix.net/2009/11/21/ies-xss-filter-creates-xss-vulnerabilities/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct cross-site
  scripting attacks on the affected system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8.");

  script_tag(name:"insight", value:"The XSS Filter used in 'response-changing mechanism' to conduct
  XSS attacks against web sites that have no inherent XSS vulnerabilities, related
  to the details of output encoding.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a cross-site scripting (XSS)
  vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.901097.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
