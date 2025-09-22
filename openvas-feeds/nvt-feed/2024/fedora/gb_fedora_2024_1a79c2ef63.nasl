# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886767");
  script_tag(name:"creation_date", value:"2024-05-27 10:47:02 +0000 (Mon, 27 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-1a79c2ef63)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-1a79c2ef63");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-1a79c2ef63");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav/pull/1216");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav/pull/1225");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav/pull/1232");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav/pull/1237");
  script_xref(name:"URL", value:"https://github.com/Cisco-Talos/clamav/pull/1240");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the FEDORA-2024-1a79c2ef63 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ClamAV 1.0.6 is a critical patch release with the following fixes:

 * Updated select Rust dependencies to the latest versions. This resolved Cargo audit complaints and included PNG parser bug fixes.

 * GitHub pull request<[link moved to references]>
 * Fixed a bug causing some text to be truncated when converting from UTF-16.

 * GitHub pull request<[link moved to references]>
 * Fixed assorted complaints identified by Coverity static analysis.

 * GitHub pull request<[link moved to references]>
 * Fixed a bug causing CVDs downloaded by the DatabaseCustomURL Freshclam config option to be pruned and then re-downloaded with every update.

 * GitHub pull request<[link moved to references]>
 * Added the new 'valhalla' database name to the list of optional databases in preparation for future work.

 * GitHub pull request<[link moved to references]>
 * Silenced a warning 'Unexpected early end-of-file' that occured when scanning some PNG files.

 * GitHub pull request<[link moved to references]>");

  script_tag(name:"affected", value:"'clamav' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-data", rpm:"clamav-data~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-doc", rpm:"clamav-doc~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-filesystem", rpm:"clamav-filesystem~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-freshclam", rpm:"clamav-freshclam~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-freshclam-debuginfo", rpm:"clamav-freshclam-debuginfo~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-lib", rpm:"clamav-lib~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-lib-debuginfo", rpm:"clamav-lib-debuginfo~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter-debuginfo", rpm:"clamav-milter-debuginfo~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~1.0.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd-debuginfo", rpm:"clamd-debuginfo~1.0.6~1.fc39", rls:"FC39"))) {
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
