# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800242");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-16 16:42:20 +0100 (Mon, 16 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0449");
  script_name("Kaspersky AntiVirus Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33788");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33561");
  script_xref(name:"URL", value:"http://www.wintercore.com/advisories/advisory_W020209.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_mandatory_keys("Kaspersky/products/installed");
  script_tag(name:"affected", value:"Kaspersky AntiVirus version 7.0.1.325 and prior on Windows.
  Kaspersky AntiVirus Workstation version 6.0.3.837 and prior on Windows.");
  script_tag(name:"insight", value:"This flaw is due to an error in the klim5.sys driver when handling Kernel
  API calls IOCTL 0x80052110 which can overwrite callback function pointers
  and execute arbitrary codes into the context of the application.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Kaspersky AntiVirus or Workstation is prone to a buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application or may cause privilege escalation.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.kaspersky.com/productupdates?chapter=146274385");
  exit(0);
}

include("version_func.inc");

kavVer = get_kb_item("Kaspersky/AV/Ver");
if(kavVer != NULL)
{
  if(version_is_less_equal(version:kavVer, test_version:"7.0.1.325")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

kavwVer = get_kb_item("Kaspersky/AV-Workstation/Ver");
if(kavwVer != NULL)
{
  if(version_is_less_equal(version:kavwVer, test_version:"6.0.3.837")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
