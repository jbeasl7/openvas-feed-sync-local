# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901043");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-2911");
  script_name("SystemTap Unprivileged Mode Multiple DoS Vulnerabilities");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2989");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36778");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=529175");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/10/21/1");
  script_xref(name:"URL", value:"http://sources.redhat.com/bugzilla/show_bug.cgi?id=10750");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=365293");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=365294");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=365413");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_systemtap_detect.nasl");
  script_mandatory_keys("SystemTap/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code and cause a denial
  of service or compromise a vulnerable system.");
  script_tag(name:"affected", value:"SystemTap version 1.0 and prior.");
  script_tag(name:"solution", value:"Apply the patch from the referenced bugzilla attachments.");
  script_tag(name:"summary", value:"SystemTap is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"insight", value:"Multiple errors occur when SystemTap is running in 'unprivileged' mode.

  - Error within the handling of the unwind table and CIE/CFI records

  - A buffer overflow error when processing a long number of parameters

  - A stack overflow when processing DWARF information");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

systapVer = get_kb_item("SystemTap/Ver");
if(!systapVer)
  exit(0);

if(version_is_less_equal(version:systapVer, test_version:"1.0")){
  report = report_fixed_ver(installed_version:systapVer, vulnerable_range:"Less than or equal to 1.0");
  security_message(port: 0, data: report);
}
