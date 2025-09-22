# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100048");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-03-16 12:53:50 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-1204");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34108");
  script_name("Tiki Wiki CMS Groupware 'tiki-orphan_pages.php' XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");

  script_tag(name:"solution", value:"Upgrade to latest version.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site and to steal cookie-based
  authentication credentials.");

  script_tag(name:"affected", value:"Tiki Wiki CMS Groupware 2.2 through 3.0 beta1 are vulnerable.");

  script_tag(name:"summary", value:"Tiki Wiki CMS Groupware is prone to a cross-site scripting vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Tiki Wiki CMS Groupware < 2.4 Multiple XSS
  Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.800266).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
