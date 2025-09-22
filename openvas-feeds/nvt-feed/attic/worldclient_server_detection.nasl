# SPDX-FileCopyrightText: 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10745");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-0660");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WorldClient for MDaemon Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=WorldClient");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1462");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/823");

  script_tag(name:"solution", value:"Make sure all usernames and passwords are adequately long and
  that only authorized networks have access to this web server's port number
  (block the web server's port number on your firewall).");

  script_tag(name:"summary", value:"We detected the remote web server is
  running WorldClient for MDaemon. This web server enables attackers
  with the proper username and password combination to access locally
  stored mailboxes.

  In addition, earlier versions of WorldClient suffer from buffer overflow
  vulnerabilities, and web traversal problems (if those are found the Risk
  factor is higher).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
