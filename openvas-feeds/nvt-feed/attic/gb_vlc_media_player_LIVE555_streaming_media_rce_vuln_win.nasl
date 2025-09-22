# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814317");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2018-4013");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 17:21:00 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-11-02 13:55:59 +0530 (Fri, 02 Nov 2018)");

  script_name("VLC Media Player LIVE555 RTSP Server RCE Vulnerability - Windows");

  script_tag(name:"summary", value:"VLC Media Player is prone to a remote code execution (RCE)
  vulnerability.

  This VT has been deprecated since VLC Media player is not affected.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the function that parses HTTP headers for
  tunneling RTSP over HTTP. An attacker may create a packet containing multiple 'Accept:' or
  'x-sessioncookie' strings which could cause a stack buffer overflow in the function
  'lookForHeader'");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause a
  stack-based buffer overflow by sending a specially crafted packet, resulting in code execution.");

  script_tag(name:"affected", value:"VLC Media Player versions 3.0.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://blog.talosintelligence.com/2018/10/vulnerability-spotlight-live-networks.html");
  script_xref(name:"URL", value:"https://it.slashdot.org/comments.pl?sid=12787146&cid=57515512");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);