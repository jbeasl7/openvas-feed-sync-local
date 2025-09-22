# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902285");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-0096");
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (2501696)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2501696");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46055");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2501696.mspx");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/46055.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof content,
  disclose information or take any action that the user could take on the
  affected Web site on behalf of the targeted user.");

  script_tag(name:"affected", value:"Internet Explorer Version 5.x, 6.x, 7.x and 8.x");

  script_tag(name:"insight", value:"The vulnerability exists due to the way MHTML interprets MIME-formatted
  requests for content blocks within a document, which allows an attacker to
  inject a client-side script in the response of a Web request run in the
  context of the victim's Internet Explorer.");

  script_tag(name:"summary", value:"Internet Explorer is prone to an information disclosure vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.902409.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66);
