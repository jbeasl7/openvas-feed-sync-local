# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.2210151710210160");
  script_cve_id("CVE-2026-26130");
  script_tag(name:"creation_date", value:"2026-03-31 04:51:57 +0000 (Tue, 31 Mar 2026)");
  script_version("2026-03-31T06:09:03+0000");
  script_tag(name:"last_modification", value:"2026-03-31 06:09:03 +0000 (Tue, 31 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-10 18:18:42 +0000 (Tue, 10 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-22e517fe60)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-22e517fe60");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-22e517fe60");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2446428");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.14/9.0.115.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.14/9.0.14.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet9.0' package(s) announced via the FEDORA-2026-22e517fe60 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the March 2026 release of .NET 9.

Release Notes:

- SDK: [link moved to references]
- Runtime: [link moved to references]");

  script_tag(name:"affected", value:"'dotnet9.0' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-9.0", rpm:"aspnetcore-runtime-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-dbg-9.0", rpm:"aspnetcore-runtime-dbg-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-targeting-pack-9.0", rpm:"aspnetcore-targeting-pack-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-9.0", rpm:"dotnet-apphost-pack-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-9.0-debuginfo", rpm:"dotnet-apphost-pack-9.0-debuginfo~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-9.0", rpm:"dotnet-hostfxr-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-9.0-debuginfo", rpm:"dotnet-hostfxr-9.0-debuginfo~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-9.0", rpm:"dotnet-runtime-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-9.0-debuginfo", rpm:"dotnet-runtime-9.0-debuginfo~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-dbg-9.0", rpm:"dotnet-runtime-dbg-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-9.0", rpm:"dotnet-sdk-9.0~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-9.0-debuginfo", rpm:"dotnet-sdk-9.0-debuginfo~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-9.0-source-built-artifacts", rpm:"dotnet-sdk-9.0-source-built-artifacts~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-aot-9.0", rpm:"dotnet-sdk-aot-9.0~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-aot-9.0-debuginfo", rpm:"dotnet-sdk-aot-9.0-debuginfo~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-dbg-9.0", rpm:"dotnet-sdk-dbg-9.0~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-targeting-pack-9.0", rpm:"dotnet-targeting-pack-9.0~9.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-templates-9.0", rpm:"dotnet-templates-9.0~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet9.0", rpm:"dotnet9.0~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet9.0-debugsource", rpm:"dotnet9.0-debugsource~9.0.115~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netstandard-targeting-pack-2.1", rpm:"netstandard-targeting-pack-2.1~9.0.115~1.fc43", rls:"FC43"))) {
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
