# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02366.2");
  script_cve_id("CVE-2025-22872");
  script_tag(name:"creation_date", value:"2025-07-31 04:22:03 +0000 (Thu, 31 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02366-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02366-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502366-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244035");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040952.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2025:02366-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for docker fixes the following issues:

Update to Docker 28.2.2-ce (bsc#1243833, bsc#1242114):

- CVE-2025-22872: golang.org/x/net/html: incorrectly interpreted tags can cause content to be placed wrong scope during DOM construction (bsc#1241830).

Other bugfixes:

- Always clear SUSEConnect suse_* secrets when starting containers (bsc#1244035).
- SUSEConnect secrets fails in SLES rootless docker containers (bsc#1240150).");

  script_tag(name:"affected", value:"'docker' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~28.2.2_ce~98.134.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~28.2.2_ce~98.134.1", rls:"SLES12.0SP5"))) {
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
