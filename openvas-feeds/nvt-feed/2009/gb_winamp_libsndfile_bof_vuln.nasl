# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900558");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1788", "CVE-2009-1791");
  script_name("Winamp libsndfile Buffer Overflow Vulnerability");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_tag(name:"impact", value:"Attackers may leverage this issue by executing arbitrary codes in the
  context of the affected application via specially crafted VOC, AIFF
  files and can cause denial of service.");
  script_tag(name:"affected", value:"Winamp version 5.552 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is generated due to boundary error in 'voc_read_header()' and
  'aiff_read_header()' functions in libsndfile.dll while processing VOC
  and AIFF files with invalid header values.");
  script_tag(name:"summary", value:"Winamp is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution", value:"Upgrade to the latest libsndfile version.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35076");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34978");
  script_xref(name:"URL", value:"http://trapkit.de/advisories/TKADV2009-006.txt");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1324");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer)
  exit(0);

if(version_is_less_equal(version:winampVer, test_version:"5.5.5.2435")){
   report = report_fixed_ver(installed_version:winampVer, vulnerable_range:"Less than or equal to 5.5.5.2435");
   security_message(port: 0, data: report);
}
