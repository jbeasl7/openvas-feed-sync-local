# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803306");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2013-1490");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-02-06 10:54:26 +0530 (Wed, 06 Feb 2013)");
  script_name("Oracle Java SE Unspecified Vulnerability (Feb 2013) - Windows");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jan/142");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2013-1490");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary
code via unknown vectors.");
  script_tag(name:"affected", value:"Oracle Java version 7 Update 11 on Windows");
  script_tag(name:"insight", value:"An unspecified vulnerability allows remote attackers to bypass Java
security sandbox via unknown vectors.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Oracle Java SE is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  if(jreVer == "1.7.0.11")
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
