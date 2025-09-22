# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11775");
  script_version("2025-01-17T15:39:18+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7208");
  script_cve_id("CVE-2003-1284");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Sambar CGIs path disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web application abuses");

  script_tag(name:"affected", value:"Sambar WebServer v5.3 and below.");

  script_tag(name:"solution", value:"Remove them.");

  script_tag(name:"summary", value:"environ.pl or testcgi.exe is installed. Those CGIs
  reveal the installation directory and some other information
  that could help an attacker.

  This VT has been deprecated and replaced by the VT 'Sambar default CGI info disclosure'
  (OID: 1.3.6.1.4.1.25623.1.0.80082).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
