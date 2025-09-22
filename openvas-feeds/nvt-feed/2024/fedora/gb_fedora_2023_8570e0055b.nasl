# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.8570101005598");
  script_cve_id("CVE-2023-32732");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-15 22:14:04 +0000 (Thu, 15 Jun 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-8570e0055b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8570e0055b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-8570e0055b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2214470");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grpc' package(s) announced via the FEDORA-2023-8570e0055b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for grpc-1.48.4-20.fc39.

##### **Changelog**

```
* Wed Jul 5 2023 Benjamin A. Beasley <code@musicinmybrain.net> - 1.48.4-20
- Backport fix for CVE-2023-32732 (fix RHBZ#2214470)

```");

  script_tag(name:"affected", value:"'grpc' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"grpc", rpm:"grpc~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-cli", rpm:"grpc-cli~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-cli-debuginfo", rpm:"grpc-cli-debuginfo~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-cpp", rpm:"grpc-cpp~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-cpp-debuginfo", rpm:"grpc-cpp-debuginfo~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-data", rpm:"grpc-data~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-debuginfo", rpm:"grpc-debuginfo~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-debugsource", rpm:"grpc-debugsource~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-devel", rpm:"grpc-devel~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-doc", rpm:"grpc-doc~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-plugins", rpm:"grpc-plugins~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grpc-plugins-debuginfo", rpm:"grpc-plugins-debuginfo~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio+protobuf", rpm:"python3-grpcio+protobuf~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio", rpm:"python3-grpcio~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-channelz", rpm:"python3-grpcio-channelz~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-debuginfo", rpm:"python3-grpcio-debuginfo~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-health-checking", rpm:"python3-grpcio-health-checking~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-reflection", rpm:"python3-grpcio-reflection~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-status", rpm:"python3-grpcio-status~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-testing", rpm:"python3-grpcio-testing~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-tools", rpm:"python3-grpcio-tools~1.48.4~20.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-grpcio-tools-debuginfo", rpm:"python3-grpcio-tools-debuginfo~1.48.4~20.fc39", rls:"FC39"))) {
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
