# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886965");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-06-07 06:35:03 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for rust-sd (FEDORA-2024-40ee18b2e7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-40ee18b2e7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3YKPSQ533X2LGWS4BJKND4JHVGEOMSSA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-sd'
  package(s) announced via the FEDORA-2024-40ee18b2e7 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Intuitive find & replace CLI.

  * Painless regular expressions

  sd uses regex syntax that you already know from JavaScript and Python.
  Forget about dealing with quirks of sed or awk - get productive immediately.

  * String-literal mode

  Non-regex find & replace. No more backslashes or remembering which characters
  are special and need to be escaped.

  * Easy to read, easy to write

  Find & replace expressions are split up, which makes them easy to read
  and write. No more messing with unclosed and escaped slashes.

  * Smart, common-sense defaults

  Defaults follow common sense and are tailored for typical daily use.");

  script_tag(name:"affected", value:"'rust-sd' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
