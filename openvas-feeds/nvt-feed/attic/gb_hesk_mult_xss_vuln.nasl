# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802132");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2011-5287");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HESK Multiple XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519148");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/multiple_xss_in_hesk.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103733/hesk-xss.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"insight", value:"This VT has been deprecated as a duplicate of the VT
  'HESK < 2.4.1 Multiple XSS Vulnerabilities - Active Check' (OID: 1.3.6.1.4.1.25623.1.0.103198).

  The flaws are due to improper validation of

  - input passed via the 'hesk_settings[tmp_title]' and 'hesklang[ENCODING]'
    parameters to '/inc/header.inc.php'.

  - input passed via 'hesklang[attempt]' parameter to various files in '/inc/'
    directory.

  - input appended to the URL after '/language/en/text.php', before being
  returned to the user.");

  script_tag(name:"solution", value:"Upgrade to HESK version 2.3 or later.");

  script_tag(name:"summary", value:"HESK is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of affected website.");

  script_tag(name:"affected", value:"HESK version 2.2 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
