# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.0499980102929899");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-04cb0f92bc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-04cb0f92bc");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-04cb0f92bc");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.7/8.0.107.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.7/8.0.7.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet8.0' package(s) announced via the FEDORA-2024-04cb0f92bc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the July 2024 security updates for .NET 8.

Release Notes:

- SDK: [link moved to references]
- Runtime: [link moved to references]");

  script_tag(name:"affected", value:"'dotnet8.0' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-8.0", rpm:"aspnetcore-runtime-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-dbg-8.0", rpm:"aspnetcore-runtime-dbg-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-targeting-pack-8.0", rpm:"aspnetcore-targeting-pack-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-8.0", rpm:"dotnet-apphost-pack-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-8.0-debuginfo", rpm:"dotnet-apphost-pack-8.0-debuginfo~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-host", rpm:"dotnet-host~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-host-debuginfo", rpm:"dotnet-host-debuginfo~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-8.0", rpm:"dotnet-hostfxr-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-8.0-debuginfo", rpm:"dotnet-hostfxr-8.0-debuginfo~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-8.0", rpm:"dotnet-runtime-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-8.0-debuginfo", rpm:"dotnet-runtime-8.0-debuginfo~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-dbg-8.0", rpm:"dotnet-runtime-dbg-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-8.0", rpm:"dotnet-sdk-8.0~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-8.0-debuginfo", rpm:"dotnet-sdk-8.0-debuginfo~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-8.0-source-built-artifacts", rpm:"dotnet-sdk-8.0-source-built-artifacts~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-dbg-8.0", rpm:"dotnet-sdk-dbg-8.0~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-targeting-pack-8.0", rpm:"dotnet-targeting-pack-8.0~8.0.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-templates-8.0", rpm:"dotnet-templates-8.0~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet8.0", rpm:"dotnet8.0~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet8.0-debugsource", rpm:"dotnet8.0-debugsource~8.0.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netstandard-targeting-pack-2.1", rpm:"netstandard-targeting-pack-2.1~8.0.107~1.fc40", rls:"FC40"))) {
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
