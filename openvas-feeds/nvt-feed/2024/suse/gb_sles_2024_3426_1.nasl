# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3426.1");
  script_cve_id("CVE-2017-15865", "CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381", "CVE-2022-37032", "CVE-2024-44070");
  script_tag(name:"creation_date", value:"2024-09-25 04:30:17 +0000 (Wed, 25 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 18:39:35 +0000 (Wed, 14 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3426-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243426-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230866");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-September/019517.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the SUSE-SU-2024:3426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for quagga fixes the following issues:

- CVE-2017-15865: sensitive information disclosed when malformed BGP UPDATE packets are processed. (bsc#1230866)
- CVE-2024-44070: crash when parsing Tunnel Encap attribute due to no length check. (bsc#1229438)
- CVE-2022-37032: out-of-bounds read when parsing a BGP capability message due to incorrect size check. (bsc#1202023)

Bug fixes:
- References to /var/adm/fillup-templates replaced with new %_fillupdir macro. (bsc#1069468)");

  script_tag(name:"affected", value:"'quagga' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~17.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~17.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~17.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~17.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~17.13.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~17.13.1", rls:"SLES12.0SP5"))) {
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
