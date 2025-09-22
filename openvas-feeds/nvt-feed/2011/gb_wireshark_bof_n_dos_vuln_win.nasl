# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802502");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-11-08 11:40:17 +0200 (Tue, 08 Nov 2011)");
  script_cve_id("CVE-2011-4102", "CVE-2011-4101");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Heap Based BOF and Denial of Service Vulnerabilities - Windows");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service via
  via a malformed packet.");
  script_tag(name:"affected", value:"Wireshark version 1.4.0 through 1.4.9 and 1.6.x before 1.6.3");
  script_tag(name:"insight", value:"The flaws are due to

  - An error while parsing ERF file format. This could cause wireshark to crash
    by reading a malformed packet trace file.

  - An error in dissect_infiniband_common function in
    epan/dissectors/packet-infiniband.c in the Infiniband dissector, could
    dereference a NULL pointer.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.3 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to heap based buffer overflow and denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=750645");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50481");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50486");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/11/01/9");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6476");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=39508");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=39500");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.9")||
   version_in_range(version:version, test_version:"1.6.0", test_version2:"1.6.2")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
