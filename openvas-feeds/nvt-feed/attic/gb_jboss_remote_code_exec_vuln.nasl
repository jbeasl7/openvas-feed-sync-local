# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805373");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-04-30 14:34:53 +0530 (Thu, 30 Apr 2015)");
  script_name("JBoss Application Server RCE Vulnerability");

  script_tag(name:"summary", value:"JBoss Application Server is prone to a remote code execution (RCE)
  vulnerability.

  Note: This script is temporary deprecated until check for this vulnerability was implemented.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP
  GET request and check whether it is able to execute the code remotely.");

  script_tag(name:"insight", value:"Flaw is due to the jbossass/jbossass.jsp
  script not properly sanitizing user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code in the affected system.");

  script_tag(name:"affected", value:"JBoss AS versions 3, 4, 5, 6.");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36575/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);