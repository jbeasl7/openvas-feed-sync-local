# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.66101981002911028");
  script_cve_id("CVE-2025-23419");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-66ebd291f8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-66ebd291f8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-66ebd291f8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277663");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2344198");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx, nginx-mod-fancyindex, nginx-mod-modsecurity, nginx-mod-naxsi, nginx-mod-vts' package(s) announced via the FEDORA-2025-66ebd291f8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Changes with nginx 1.26.3 05 Feb 2025

 *) Security: insufficient check in virtual servers handling with TLSv1.3
 SNI allowed to reuse SSL sessions in a different virtual server, to
 bypass client SSL certificates verification (CVE-2025-23419).

 *) Bugfix: in the ngx_http_mp4_module.
 Thanks to Nils Bars.

 *) Workaround: 'gzip filter failed to use preallocated memory' alerts
 appeared in logs when using zlib-ng.

 *) Bugfix: nginx could not build libatomic library using the library
 sources if the --with-libatomic=DIR option was used.

 *) Bugfix: nginx now ignores QUIC version negotiation packets from
 clients.

 *) Bugfix: nginx could not be built on Solaris 10 and earlier with the
 ngx_http_v3_module.

 *) Bugfixes in HTTP/3.");

  script_tag(name:"affected", value:"'nginx, nginx-mod-fancyindex, nginx-mod-modsecurity, nginx-mod-naxsi, nginx-mod-vts' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-all-modules", rpm:"nginx-all-modules~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core", rpm:"nginx-core~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-core-debuginfo", rpm:"nginx-core-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-filesystem", rpm:"nginx-filesystem~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-devel", rpm:"nginx-mod-devel~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-fancyindex", rpm:"nginx-mod-fancyindex~0.5.2~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-fancyindex-debuginfo", rpm:"nginx-mod-fancyindex-debuginfo~0.5.2~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-fancyindex-debugsource", rpm:"nginx-mod-fancyindex-debugsource~0.5.2~10.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter", rpm:"nginx-mod-http-image-filter~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-image-filter-debuginfo", rpm:"nginx-mod-http-image-filter-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl", rpm:"nginx-mod-http-perl~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-perl-debuginfo", rpm:"nginx-mod-http-perl-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter", rpm:"nginx-mod-http-xslt-filter~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-http-xslt-filter-debuginfo", rpm:"nginx-mod-http-xslt-filter-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail", rpm:"nginx-mod-mail~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-mail-debuginfo", rpm:"nginx-mod-mail-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-modsecurity", rpm:"nginx-mod-modsecurity~1.0.3~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-modsecurity-debuginfo", rpm:"nginx-mod-modsecurity-debuginfo~1.0.3~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-modsecurity-debugsource", rpm:"nginx-mod-modsecurity-debugsource~1.0.3~16.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-naxsi", rpm:"nginx-mod-naxsi~1.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-naxsi-debuginfo", rpm:"nginx-mod-naxsi-debuginfo~1.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-naxsi-debugsource", rpm:"nginx-mod-naxsi-debugsource~1.6~9.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream", rpm:"nginx-mod-stream~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-stream-debuginfo", rpm:"nginx-mod-stream-debuginfo~1.26.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-vts", rpm:"nginx-mod-vts~0.2.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-vts-debuginfo", rpm:"nginx-mod-vts-debuginfo~0.2.3~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-mod-vts-debugsource", rpm:"nginx-mod-vts-debugsource~0.2.3~3.fc41", rls:"FC41"))) {
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
