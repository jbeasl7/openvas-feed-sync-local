# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100348");
  script_version("2025-09-19T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-11-16 11:47:06 +0100 (Mon, 16 Nov 2009)");
  script_cve_id("CVE-2009-4040");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("phpMyFAQ Search Page XSS Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37020");
  script_xref(name:"URL", value:"http://www.phpmyfaq.de/advisory_2009-09-01.php");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"phpMyFAQ is prone to a cross-site scripting vulnerability because the
  application fails to properly sanitize user-supplied input.

  This VT has been deprecated as a duplicate of the following VT:

  phpMyFAQ < 2.0.17, 2.5.x < 2.5.2 XSS Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.900982)");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Versions prior to phpMyFAQ 2.5.2 and 2.0.17 are vulnerable.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);