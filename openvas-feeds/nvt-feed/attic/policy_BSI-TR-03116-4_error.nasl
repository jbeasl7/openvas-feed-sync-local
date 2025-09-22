# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.96177");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2016-03-07 09:09:05 +0100 (Mon, 07 Mar 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BSI-TR-03116-4: Errors");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Policy");

  script_tag(name:"summary", value:"List errors from Policy for BSI-TR-03116-4 Test.

  This VT has been deprecated as is not needed anymore.");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
