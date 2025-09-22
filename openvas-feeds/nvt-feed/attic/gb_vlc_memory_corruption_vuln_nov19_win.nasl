# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815724");
  script_version("2024-04-04T05:05:25+0000");
  script_cve_id("CVE-2019-18278");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-11-19 12:13:50 +0530 (Tue, 19 Nov 2019)");
  script_name("VLC Media Player Memory Corruption Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2019/10/random-bytes-in-vlc-308.html");

  script_tag(name:"summary", value:"VLC Media Player is prone to a memory corruption vulnerability.

  NOTE: This VT covers a vulnerability that was neither reproducible by vendor nor by the reporter and therefore has been deprecated.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the 'libqt' component
  when data from a faulting address controls code flow starting at
  'libqt_plugin!vlc_entry_license__3_0_0f+0x00000000003b9aba'");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers
  to cause denial of service condition or execute arbitrary code.");

  script_tag(name:"affected", value:"VLC Media Player version 3.0.8.");

  script_tag(name:"solution", value:"Vulnerability has not been confirmed.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  exit(0);
}

exit(66);