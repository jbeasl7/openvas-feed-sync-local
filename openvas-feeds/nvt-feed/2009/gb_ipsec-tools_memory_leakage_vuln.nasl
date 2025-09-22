# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900708");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1632");
  script_name("IPSec-Tools Memory Leakage Vulnerability");
  script_xref(name:"URL", value:"https://trac.ipsec-tools.net/ticket/303");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/05/12/3");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?group_id=74601&release_id=677611");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ipsec-tools_detect.nasl");
  script_mandatory_keys("IPSec/Tools/Ver");
  script_tag(name:"affected", value:"IPsec Tools version prior to 0.7.2");
  script_tag(name:"insight", value:"Multiple memory leaks are cause due to error in eay_check_x509sign function in
  'src/racoon/crypto_openssl.c' and NAT Traversal keepalive implementation in
  'src/racoon/nattraversal.c' files.");
  script_tag(name:"solution", value:"Upgrade to the latest version 0.7.2.");
  script_tag(name:"summary", value:"IPSec-Tools for Linux is prone to Memory Leakage Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause multiple memory leaks or
  memory consumption through signature verification during user authentication
  with X.509 certificates.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ipsecVer = get_kb_item("IPSec/Tools/Ver");
if(!ipsecVer)
  exit(0);

if(version_is_less(version:ipsecVer, test_version:"0.7.2")){
  report = report_fixed_ver(installed_version:ipsecVer, fixed_version:"0.7.2");
  security_message(port: 0, data: report);
}
