# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2861.1");
  script_cve_id("CVE-2020-17437");
  script_tag(name:"creation_date", value:"2022-08-24 07:59:30 +0000 (Wed, 24 Aug 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-15 15:46:40 +0000 (Tue, 15 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2861-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2861-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222861-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179908");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-August/011958.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-iscsi' package(s) announced via the SUSE-SU-2022:2861-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-iscsi fixes the following issues:

- CVE-2020-17437: Fixed an out of bounds memory access when the TCP
 urgent flag is set. (bsc#1179908).

Non-security fixes:

- Fix an issue with ARP booting when using different subnets (bsc#1058463).
- Allow target discovery using 'db' mode (bsc#1109477).");

  script_tag(name:"affected", value:"'open-iscsi' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"iscsiuio", rpm:"iscsiuio~0.7.8.2~46.17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-iscsi", rpm:"open-iscsi~2.0.873~46.17.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-isns", rpm:"open-isns~0.95~46.17.2", rls:"SLES12.0SP2"))) {
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
