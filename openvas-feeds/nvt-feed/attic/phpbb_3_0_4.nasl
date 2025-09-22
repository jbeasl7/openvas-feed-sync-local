# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100035");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpBB 'ucp.php' XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");

  script_tag(name:"solution", value:"Upgrade to newer Version if available.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to
  launch other attacks.");

  script_tag(name:"affected", value:"This issue affects phpBB 3.x, other versions may also be affected.");

  script_tag(name:"summary", value:"According to its version number, the remote version of phpbb
  is prone to a cross-site scripting vulnerability because it fails to sufficiently sanitize user-supplied data.

  UPDATE (March 13, 2009): The referenced BID is being retired because the issue cannot be exploited as described.");

  script_tag(name:"deprecated", value:TRUE);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33995");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66);
