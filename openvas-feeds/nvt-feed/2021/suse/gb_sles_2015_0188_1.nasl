# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0188.1");
  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0188-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0188-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150188-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2015:0188-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Clamav was updated to version 0.98.5:

Support for the XDP file format and extracting, decoding, and scanning
 PDF files within XDP files.

Addition of shared library support for LLVM versions 3.1 - 3.5 for the
 purpose of just-in-time(JIT) compilation of ClamAV bytecode signatures.

Enhancements to the clambc command line utility to assist ClamAV
 bytecode signature authors by providing introspection into compiled
 bytecode programs.

Resolution of many of the warning messages from ClamAV compilation.

Improved detection of malicious PE files (bnc#906770, CVE-2014-9050)

Security fix for ClamAV crash when using 'clamscan -a'.

Security fix for ClamAV crash when scanning maliciously crafted yoda's
 crypter files (bnc#906077, CVE-2013-6497).

ClamAV 0.98.5 now works with OpenSSL in FIPS compliant mode (bnc#904207).

Fix server socket setup code in clamd (bnc#903489).

Change updateclamconf to prefer the state of the old config file even
 for commented-out options (bnc#903719) (bnc#908731).");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.5~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.98.5~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.98.5~6.1", rls:"SLES12.0"))) {
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
