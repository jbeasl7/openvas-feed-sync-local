# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801041");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3837");
  script_name("Eureka Email Stack-Based Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53940");
  script_xref(name:"URL", value:"http://secunia.com/advisories/product/27632/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3025");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0910-exploits/eurekamc-dos.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_eureka_email_detect.nasl");
  script_mandatory_keys("EurekaEmail/Ver");
  script_tag(name:"affected", value:"Eureka Email version 2.2q and prior.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the processing POP3 responses.
This can be exploited to cause a stack-based buffer overflow via an overly long
error response.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Eureka Email is prone to stack-based buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to crash an
affected client or execute arbitrary code by tricking a user into connecting to
a malicious POP3 server.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

eeVer = get_kb_item("EurekaEmail/Ver");
if(eeVer != NULL)
{
  # Eureka Email 2.2q (2.2.0.1)
  if(version_is_less_equal(version:eeVer, test_version:"2.2.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
