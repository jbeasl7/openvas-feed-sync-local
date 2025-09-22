# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800634");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1959");
  script_name("Irssi Off-by-one Read/Write DoS Vulnerability - Linux");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_irssi_detect_lin.nasl");
  script_mandatory_keys("Irssi/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause memory
corruption, and can crash an affected application by tricking a user into
connecting to a malicious IRC server.");
  script_tag(name:"affected", value:"Irssi version 0.8.13 and prior on Linux");
  script_tag(name:"insight", value:"Off-by-one error in the 'event_wallops' function in
fe-common/irc/fe-events.c when processing empty commands sent by IRC servers,
which triggers a one-byte buffer under-read and a one-byte buffer underflow.");
  script_tag(name:"summary", value:"Irssi is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1596");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35399");
  script_xref(name:"URL", value:"http://bugs.irssi.org/index.php?do=details&task_id=662");
  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2009/Jun/1022410.html");
  exit(0);
}

include("version_func.inc");

irssiVer = get_kb_item("Irssi/Lin/Ver");

if(irssiVer != NULL)
{
  if(version_is_less_equal(version:irssiVer, test_version:"0.8.13")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
