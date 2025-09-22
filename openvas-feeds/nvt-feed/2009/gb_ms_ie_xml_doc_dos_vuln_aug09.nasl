# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800863");
  script_version("2024-02-19T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2668");
  script_name("Microsoft Internet Explorer XML Document DoS Vulnerability (Aug 2009)");
  script_xref(name:"URL", value:"http://websecurity.com.ua/3216/");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2009-07/0193.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/EXE/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause
  Denial of Service in the context of an affected application.");

  script_tag(name:"affected", value:"Internet Explorer version 6.x to 6.0.2900.2180 and 7.x to
  7.0.6000.16473.");

  script_tag(name:"insight", value:"The flaw exists via an XML document composed of a long series
  of start-tags with no corresponding end-tags and it leads to CPU consumption.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to a denial
  of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/EXE/Ver");

if(!isnull(ieVer))
{
  if(version_in_range(version:ieVer, test_version:"6.0", test_version2:"6.0.2900.2180") ||
     version_in_range(version:ieVer, test_version:"7.0", test_version2:"7.0.6000.16473")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
