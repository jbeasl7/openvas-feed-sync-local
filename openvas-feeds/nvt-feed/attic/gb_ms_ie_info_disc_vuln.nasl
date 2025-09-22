# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801606");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2010-3886");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)");
  script_name("Microsoft Internet Explorer 'mshtml.dll' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2010-06/0259.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41247");
  script_xref(name:"URL", value:"http://reversemode.com/index.php?option=com_content&task=view&id=68&Itemid=1");
  script_xref(name:"URL", value:"http://www.eeye.com/Resources/Security-Center/Research/Zero-Day-Tracker/2010/20100630");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain access to
  sensitive information that may aid in further attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8 and prior.");

  script_tag(name:"insight", value:"The CTimeoutEventList::InsertIntoTimeoutList function in Microsoft
  mshtml.dll uses a certain pointer value as part of producing Timer ID values for the setTimeout and
  setInterval methods in VBScript and JScript, which allows remote attackers to obtain sensitive information
  about the heap memory addresses used by the Internet Explorer application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Internet Explorer is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"deprecated", value:TRUE); # Plugin may result in FP

  exit(0);
}

exit(66); # Plugin may result in FP
