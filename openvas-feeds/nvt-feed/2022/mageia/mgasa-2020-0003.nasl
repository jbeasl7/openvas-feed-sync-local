# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0003");
  script_cve_id("CVE-2019-17068", "CVE-2019-17069");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-08 15:06:09 +0000 (Tue, 08 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0003");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0003.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25760");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-08/msg00170.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-10/msg00047.html");
  script_xref(name:"URL", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'putty' package(s) announced via the MGASA-2020-0003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated putty package fixes security vulnerabilities:

Two separate vulnerabilities affecting the obsolete SSH-1 protocol, both
available before host key checking.

Vulnerability in all the SSH client tools (PuTTY, Plink, PSFTP, and PSCP)
if a malicious program can impersonate Pageant.

Crash in GSSAPI / Kerberos key exchange triggered if the server provided
an ordinary SSH host key as part of the exchange.

Insufficient handling of terminal escape sequences, that should delimit
the pasted data in bracketed paste mode (CVE-2019-17068).

Possible information leak caused by SSH-1 disconnection messages
(CVE-2019-17069).

The putty package has been updated to version 0.73, fixing these issues
and other bugs.");

  script_tag(name:"affected", value:"'putty' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.73~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
