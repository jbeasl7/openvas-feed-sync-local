# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124045");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2022-03-25 14:46:45 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2021-43085");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("OpenSSL Insecure Permissions Vulnerability (CVE-2021-43085) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");

  script_tag(name:"summary", value:"OpenSSL is prone to an insecure permissions vulnerability.

  This VT has been deprecated since further investigation showed that it was not a security
  issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An insecure permissions vulnerability exists in OpenSSL due to
  an error in the implementation of the CMAC_Final() function.");

  script_tag(name:"affected", value:"OpenSSL version 3.0.0.");

  script_tag(name:"solution", value:"No solution is required.

  Note: Further investigation showed that it was not a security issue.");

  script_xref(name:"URL", value:"https://github.com/openssl/openssl/issues/16873");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
