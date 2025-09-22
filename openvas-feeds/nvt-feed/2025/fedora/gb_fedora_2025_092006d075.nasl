# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.092006100075");
  script_tag(name:"creation_date", value:"2025-06-23 04:14:10 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-06-23T05:41:09+0000");
  script_tag(name:"last_modification", value:"2025-06-23 05:41:09 +0000 (Mon, 23 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-092006d075)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-092006d075");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-092006d075");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.6/9.0.107.md");
  script_xref(name:"URL", value:"https://github.com/dotnet/core/blob/main/release-notes/9.0/9.0.6/9.0.6.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet9.0' package(s) announced via the FEDORA-2025-092006d075 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is the .NET monthly update for June 2025.

Release Notes:

- SDK: [link moved to references]
- Runtime: [link moved to references]");

  script_tag(name:"affected", value:"'dotnet9.0' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-9.0", rpm:"aspnetcore-runtime-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-runtime-dbg-9.0", rpm:"aspnetcore-runtime-dbg-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aspnetcore-targeting-pack-9.0", rpm:"aspnetcore-targeting-pack-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-9.0", rpm:"dotnet-apphost-pack-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-apphost-pack-9.0-debuginfo", rpm:"dotnet-apphost-pack-9.0-debuginfo~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-host", rpm:"dotnet-host~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-host-debuginfo", rpm:"dotnet-host-debuginfo~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-9.0", rpm:"dotnet-hostfxr-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-hostfxr-9.0-debuginfo", rpm:"dotnet-hostfxr-9.0-debuginfo~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-9.0", rpm:"dotnet-runtime-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-9.0-debuginfo", rpm:"dotnet-runtime-9.0-debuginfo~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-runtime-dbg-9.0", rpm:"dotnet-runtime-dbg-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-9.0", rpm:"dotnet-sdk-9.0~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-9.0-debuginfo", rpm:"dotnet-sdk-9.0-debuginfo~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-9.0-source-built-artifacts", rpm:"dotnet-sdk-9.0-source-built-artifacts~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-aot-9.0", rpm:"dotnet-sdk-aot-9.0~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-aot-9.0-debuginfo", rpm:"dotnet-sdk-aot-9.0-debuginfo~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-sdk-dbg-9.0", rpm:"dotnet-sdk-dbg-9.0~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-targeting-pack-9.0", rpm:"dotnet-targeting-pack-9.0~9.0.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet-templates-9.0", rpm:"dotnet-templates-9.0~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet9.0", rpm:"dotnet9.0~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dotnet9.0-debugsource", rpm:"dotnet9.0-debugsource~9.0.107~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netstandard-targeting-pack-2.1", rpm:"netstandard-targeting-pack-2.1~9.0.107~1.fc41", rls:"FC41"))) {
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
