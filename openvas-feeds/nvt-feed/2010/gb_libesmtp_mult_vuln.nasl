# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:stafford.uklinux:libesmtp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800497");
  script_version("2023-07-28T16:09:07+0000");
  script_cve_id("CVE-2010-1194", "CVE-2010-1192");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("libESMTP <= 1.0.4 Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=571817");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/03/09/3");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/03/03/6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/attachment.cgi?id=399131&action=edit");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_libesmtp_detect.nasl");
  script_mandatory_keys("libesmtp/detected");

  script_tag(name:"impact", value:"Attackers can exploit this issue to conduct man-in-the-middle attacks to
  spoof arbitrary SSL servers and to spoof trusted certificates.");

  script_tag(name:"affected", value:"libESMTP version 1.0.4 and prior.");

  script_tag(name:"solution", value:"Apply the update/patch from the references.");

  script_tag(name:"summary", value:"libESMTP is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'match_component()' function in 'smtp-tls.c' when processing
  substrings. It treats two strings as equal if one is a substring of the
  other, which allows attackers to spoof trusted certificates via a crafted
  subjectAltName.

  - An error in handling of 'X.509 certificate'. It does not properly
  handle a '&qt?&qt' character in a domain name in the 'subject&qts Common Name'
  field of an X.509 certificate, which allows man-in-the-middle attackers to
  spoof arbitrary SSL servers via a crafted certificate.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
   exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version:version, test_version:"1.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references", install_path:location, vulnerable_range:"Less than or equal to 1.0.4");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
