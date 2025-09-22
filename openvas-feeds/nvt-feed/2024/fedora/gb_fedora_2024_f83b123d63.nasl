# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886531");
  script_cve_id("CVE-2024-27982");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:43 +0000 (Mon, 27 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-f83b123d63)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f83b123d63");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f83b123d63");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273352");
  script_xref(name:"URL", value:"https://github.com/nodejs/llhttp/releases/tag/release%2Fv9.2.0");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/april-2024-security-releases/#http-request-smuggling-via-content-length-obfuscation---cve-2024-27982---medium");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'llhttp, python-aiohttp, uxplay' package(s) announced via the FEDORA-2024-f83b123d63 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update `llhttp` to 9.2.1, fixing [CVE-2024-27982]([link moved to references]).

Additionally, `llhttp` 9.2.0 contained [a number of bug fixes]([link moved to references]).

Backport `llhttp` 9.2.1 support to `python-aiohttp` 3.9.3.");

  script_tag(name:"affected", value:"'llhttp, python-aiohttp, uxplay' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"llhttp", rpm:"llhttp~9.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llhttp-debuginfo", rpm:"llhttp-debuginfo~9.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llhttp-debugsource", rpm:"llhttp-debugsource~9.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llhttp-devel", rpm:"llhttp-devel~9.2.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp", rpm:"python-aiohttp~3.9.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aiohttp-debugsource", rpm:"python-aiohttp-debugsource~3.9.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp+speedups", rpm:"python3-aiohttp+speedups~3.9.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp", rpm:"python3-aiohttp~3.9.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-aiohttp-debuginfo", rpm:"python3-aiohttp-debuginfo~3.9.3~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uxplay", rpm:"uxplay~1.68.2~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uxplay-debuginfo", rpm:"uxplay-debuginfo~1.68.2~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uxplay-debugsource", rpm:"uxplay-debugsource~1.68.2~3.fc39", rls:"FC39"))) {
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
