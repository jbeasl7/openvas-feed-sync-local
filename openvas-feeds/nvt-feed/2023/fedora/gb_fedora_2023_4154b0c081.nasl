# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884845");
  script_tag(name:"creation_date", value:"2023-09-22 01:15:40 +0000 (Fri, 22 Sep 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2023-4154b0c081)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-4154b0c081");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-4154b0c081");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.22/6.0.122.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/6.0/6.0.22/6.0.22.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet6.0' package(s) announced via the FEDORA-2023-4154b0c081 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the monthly update for .NET 6 for September 2023.

Release notes:

- Runtime: [link moved to references]
- SDK: [link moved to references]");

  script_tag(name:"affected", value:"'dotnet6.0' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-6.0", rpm:"aspnetcore-runtime-6.0~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-targeting-pack-6.0", rpm:"aspnetcore-targeting-pack-6.0~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet", rpm:"dotnet~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-6.0", rpm:"dotnet-apphost-pack-6.0~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-6.0-debuginfo", rpm:"dotnet-apphost-pack-6.0-debuginfo~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-host", rpm:"dotnet-host~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-host-debuginfo", rpm:"dotnet-host-debuginfo~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-6.0", rpm:"dotnet-hostfxr-6.0~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-6.0-debuginfo", rpm:"dotnet-hostfxr-6.0-debuginfo~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-6.0", rpm:"dotnet-runtime-6.0~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-6.0-debuginfo", rpm:"dotnet-runtime-6.0-debuginfo~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-6.0", rpm:"dotnet-sdk-6.0~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-6.0-debuginfo", rpm:"dotnet-sdk-6.0-debuginfo~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-6.0-source-built-artifacts", rpm:"dotnet-sdk-6.0-source-built-artifacts~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-targeting-pack-6.0", rpm:"dotnet-targeting-pack-6.0~6.0.22~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-templates-6.0", rpm:"dotnet-templates-6.0~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet6.0", rpm:"dotnet6.0~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet6.0-debuginfo", rpm:"dotnet6.0-debuginfo~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet6.0-debugsource", rpm:"dotnet6.0-debugsource~6.0.122~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netstandard-targeting-pack-2.1", rpm:"netstandard-targeting-pack-2.1~6.0.122~1.fc39", rls:"FC39"))) {
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
