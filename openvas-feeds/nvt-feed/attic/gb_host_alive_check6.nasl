# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108220");
  script_version("2024-05-08T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-08 05:05:32 +0000 (Wed, 08 May 2024)");
  script_tag(name:"creation_date", value:"2017-08-17 11:18:02 +0200 (Thu, 17 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mark host as dead if going offline (failed ICMP ping) during scan - Phase 6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"This VT has been deprecated and is therefore no longer
  functional.");

  script_tag(name:"insight", value:"As an alternative please:

  - Update the software on the scanner host to version 22.04 or later

  - Configure the system to use Boreas (already configured if using the Greenbone Operating System
  22.04+)

  - Use / configure the 'max_vts_timeouts' scanner preference accordingly");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
