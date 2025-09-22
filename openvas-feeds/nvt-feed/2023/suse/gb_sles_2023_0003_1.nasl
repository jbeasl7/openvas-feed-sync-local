# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0003.1");
  script_tag(name:"creation_date", value:"2023-01-03 04:18:22 +0000 (Tue, 03 Jan 2023)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0003-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230003-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206622");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-January/013409.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ca-certificates-mozilla' package(s) announced via the SUSE-SU-2023:0003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ca-certificates-mozilla fixes the following issues:

- Updated to 2.60 state of Mozilla SSL root CAs (bsc#1206622)
 Removed CAs:
 - Global Chambersign Root
 - EC-ACC
 - Network Solutions Certificate Authority
 - Staat der Nederlanden EV Root CA
 - SwissSign Platinum CA - G2
 Added CAs:
 - DIGITALSIGN GLOBAL ROOT ECDSA CA
 - DIGITALSIGN GLOBAL ROOT RSA CA
 - Security Communication ECC RootCA1
 - Security Communication RootCA3
 Changed trust:
 - TrustCor certificates only trusted up to Nov 30 (bsc#1206212)

- Removed CAs (bsc#1206212) as most code does not handle 'valid before nov 30 2022'
 and it is not clear how many certs were issued for SSL middleware by TrustCor:
 - TrustCor RootCert CA-1
 - TrustCor RootCert CA-2
 - TrustCor ECA-1");

  script_tag(name:"affected", value:"'ca-certificates-mozilla' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~2.60~150000.4.38.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~2.60~150000.4.38.1", rls:"SLES15.0SP1"))) {
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
