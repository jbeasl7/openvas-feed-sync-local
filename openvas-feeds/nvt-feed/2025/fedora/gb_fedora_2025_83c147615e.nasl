# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.8399147615101");
  script_tag(name:"creation_date", value:"2025-03-24 04:04:42 +0000 (Mon, 24 Mar 2025)");
  script_version("2025-03-24T05:38:38+0000");
  script_tag(name:"last_modification", value:"2025-03-24 05:38:38 +0000 (Mon, 24 Mar 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-83c147615e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-83c147615e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-83c147615e");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.14/8.0.114.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.14/8.0.14.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet8.0' package(s) announced via the FEDORA-2025-83c147615e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the monthly update for .NET for March 2025.

Release Notes:

- SDK [link moved to references]
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

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-8.0", rpm:"aspnetcore-runtime-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-dbg-8.0", rpm:"aspnetcore-runtime-dbg-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-targeting-pack-8.0", rpm:"aspnetcore-targeting-pack-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-8.0", rpm:"dotnet-apphost-pack-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-8.0-debuginfo", rpm:"dotnet-apphost-pack-8.0-debuginfo~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-8.0", rpm:"dotnet-hostfxr-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-8.0-debuginfo", rpm:"dotnet-hostfxr-8.0-debuginfo~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-8.0", rpm:"dotnet-runtime-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-8.0-debuginfo", rpm:"dotnet-runtime-8.0-debuginfo~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-dbg-8.0", rpm:"dotnet-runtime-dbg-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-8.0", rpm:"dotnet-sdk-8.0~8.0.114~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-8.0-debuginfo", rpm:"dotnet-sdk-8.0-debuginfo~8.0.114~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-8.0-source-built-artifacts", rpm:"dotnet-sdk-8.0-source-built-artifacts~8.0.114~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-dbg-8.0", rpm:"dotnet-sdk-dbg-8.0~8.0.114~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-targeting-pack-8.0", rpm:"dotnet-targeting-pack-8.0~8.0.14~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-templates-8.0", rpm:"dotnet-templates-8.0~8.0.114~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet8.0", rpm:"dotnet8.0~8.0.114~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet8.0-debugsource", rpm:"dotnet8.0-debugsource~8.0.114~1.fc40", rls:"FC40"))) {
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
