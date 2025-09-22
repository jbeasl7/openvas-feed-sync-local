# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2690.1");
  script_cve_id("CVE-2017-11108", "CVE-2017-11541", "CVE-2017-11542", "CVE-2017-11543", "CVE-2017-13011");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:52 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-14 20:17:06 +0000 (Thu, 14 Sep 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2690-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172690-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057247");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-October/003283.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2017:2690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump fixes the following issues:

Security issues fixed:

- CVE-2017-11108: Crafted input allowed remote DoS (bsc#1047873)
- CVE-2017-11541: Prevent a heap-based buffer over-read in the lldp_print function in print-lldp.c, related to util-print.c (bsc#1057247).
- CVE-2017-11542: Prevent a heap-based buffer over-read in the pimv1_print function in print-pim.c (bsc#1057247).
- CVE-2017-11543: Prevent a buffer overflow in the sliplink_print function in print-sl.c (bsc#1057247).
- CVE-2017-13011: Several protocol parsers in tcpdump could have caused a buffer overflow in util-print.c:bittok2str_internal() (bsc#1057247).");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~3.9.8~1.30.5.1", rls:"SLES11.0SP4"))) {
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
