# SPDX-FileCopyrightText: 2005 Beyond Security
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12639");
  script_version("2023-08-01T13:29:10+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10654");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10655");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("MySQL 'zero-length password' Authentication Bypass Vulnerability (MySQL Protocol)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Beyond Security");
  script_family("Default Accounts");

  script_tag(name:"summary", value:"It is possible to bypass password authentication for a database
  user using a crafted authentication packet with a zero-length password

  Note: In order to use this script, the MySQL daemon has to allow connection from the
  scanning IP address");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
