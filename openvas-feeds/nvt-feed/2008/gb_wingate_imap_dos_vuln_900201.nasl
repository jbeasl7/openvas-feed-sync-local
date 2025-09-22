# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900201");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3606");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("WinGate IMAP Server Buffer Overflow Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1020644");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30606");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/44370");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31442/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/495264");

  script_tag(name:"summary", value:"Qbik WinGate is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"The vulnerability is due to a boundary error in the processing
  of IMAP commands. This can be exploited by issuing an IMAP LIST command with an overly long argument.");

  script_tag(name:"affected", value:"WinGate 6.2.2 and prior versions on Windows (All).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"impact", value:"Exploiting this issue will consume computer resources and deny
  access to legitimate users or to potentially compromise a vulnerable system or may allow execution
  of arbitrary code.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  if("WinGate" >< entry) {

    winGateName = registry_get_sz(item:"DisplayName", key:key + entry);

    if(winGateName && egrep(pattern:"WinGate 6\.[01](\..*)?|6\.2(\.[0-2])?$", string:winGateName)) {
      security_message(port:0);
      exit(0);
    }
    exit(99);
  }
}

exit(0);