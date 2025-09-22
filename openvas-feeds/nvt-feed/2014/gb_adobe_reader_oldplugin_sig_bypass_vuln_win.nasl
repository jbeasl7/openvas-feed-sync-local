# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804627");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2003-0142");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-05 10:39:40 +0530 (Thu, 05 Jun 2014)");
  script_name("Adobe Reader Old Plugin Signature Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to plugin signature bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to error that plug-ins with signatures used for older
versions of Acrobat can also be loaded.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to submit a modified plug-in to
bypass signature checks and execute malicious code on the system.");
  script_tag(name:"affected", value:"Adobe Reader 6.x version on Windows.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/689835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/328224");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_old_adobe_reader_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader-Old/Ver");
  exit(0);
}

include("host_details.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer =~ "^6\.")
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
