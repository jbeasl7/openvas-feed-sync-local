# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902419");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-0916", "CVE-2011-0918", "CVE-2011-0919", "CVE-2011-0920");

  script_name("IBM Lotus Domino Multiple Remote Buffer Overflow Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code in the context of the Lotus Domino server process or bypass authentication.");

  script_tag(name:"affected", value:"IBM Lotus Domino versions 8.5.3 prior");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Stack overflow in the SMTP service, which allows remote attackers to
  execute arbitrary code via long arguments in a filename parameter in a
  malformed MIME e-mail message.

  - Buffer overflow in nLDAP.exe, which allows remote attackers to execute
  arbitrary code via an LDAP Bind operation.

  - Stack  overflow in the NRouter service, which allows remote attackers to
  execute arbitrary code via long filenames associated with Content-ID and
  ATTACH:CID headers in attachments in malformed calendar-request e-mail
  messages.

  - Multiple stack overflows in the POP3 and IMAP services, which allows
  remote attackers to execute arbitrary code via non-printable characters
  in an envelope sender address.

  - The Remote Console, when a certain unsupported configuration involving UNC
  share pathnames is used, allows remote attackers to bypass authentication
  and execute arbitrary code via unspecified vectors.");

  script_tag(name:"solution", value:"Upgrade to version 8.5.2 FP3 or 8.5.3 or later.");

  script_tag(name:"summary", value:"IBM Lotus Domino Server is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43247");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43224");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-045/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-049/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-047/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-046/");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21461514");
  script_xref(name:"URL", value:"http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=23&Itemid=23");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"8.5.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"8.5.2 FP3/8.5.3" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
