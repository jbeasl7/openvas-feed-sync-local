# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.347164100102199");
  script_cve_id("CVE-2024-47609");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-347164df1c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-347164df1c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-347164df1c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316020");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-hyper-rustls, rust-reqwest, rust-rustls-native-certs, rust-rustls-native-certs0.7, rust-tonic, rust-tonic-build, rust-tonic-types, rust-tower, rust-tower0.4, rust-tower-http, rust-tower-http0.5' package(s) announced via the FEDORA-2024-347164df1c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the hyper-rustls crate to version 0.27.3.
- Update the reqwest crate to version 0.12.8.
- Update the rustls-native-certs crate to version 0.8.0 and add a compat package for version 0.7.
- Update the tonic, tonic-build, and tonic-types crates to version 0.12.3.
- Update the tower crate to version 0.5.1 and add a compat package for version 0.4.
- Update the tower-http crate to version 0.6.1 and add a compat package for version 0.5.");

  script_tag(name:"affected", value:"'rust-hyper-rustls, rust-reqwest, rust-rustls-native-certs, rust-rustls-native-certs0.7, rust-tonic, rust-tonic-build, rust-tonic-types, rust-tower, rust-tower0.4, rust-tower-http, rust-tower-http0.5' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+default-devel", rpm:"rust-hyper-rustls+default-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+http1-devel", rpm:"rust-hyper-rustls+http1-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+http2-devel", rpm:"rust-hyper-rustls+http2-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+log-devel", rpm:"rust-hyper-rustls+log-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+logging-devel", rpm:"rust-hyper-rustls+logging-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+native-tokio-devel", rpm:"rust-hyper-rustls+native-tokio-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+ring-devel", rpm:"rust-hyper-rustls+ring-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+rustls-native-certs-devel", rpm:"rust-hyper-rustls+rustls-native-certs-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+tls12-devel", rpm:"rust-hyper-rustls+tls12-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+webpki-roots-devel", rpm:"rust-hyper-rustls+webpki-roots-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls+webpki-tokio-devel", rpm:"rust-hyper-rustls+webpki-tokio-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls", rpm:"rust-hyper-rustls~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hyper-rustls-devel", rpm:"rust-hyper-rustls-devel~0.27.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+__internal_proxy_sys_no_cache-devel", rpm:"rust-reqwest+__internal_proxy_sys_no_cache-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+__rustls-devel", rpm:"rust-reqwest+__rustls-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+__rustls-ring-devel", rpm:"rust-reqwest+__rustls-ring-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+__tls-devel", rpm:"rust-reqwest+__tls-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+blocking-devel", rpm:"rust-reqwest+blocking-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+charset-devel", rpm:"rust-reqwest+charset-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+cookies-devel", rpm:"rust-reqwest+cookies-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+default-devel", rpm:"rust-reqwest+default-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+default-tls-devel", rpm:"rust-reqwest+default-tls-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+deflate-devel", rpm:"rust-reqwest+deflate-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+gzip-devel", rpm:"rust-reqwest+gzip-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+h2-devel", rpm:"rust-reqwest+h2-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+hickory-dns-devel", rpm:"rust-reqwest+hickory-dns-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+http2-devel", rpm:"rust-reqwest+http2-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+json-devel", rpm:"rust-reqwest+json-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+multipart-devel", rpm:"rust-reqwest+multipart-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+native-tls-alpn-devel", rpm:"rust-reqwest+native-tls-alpn-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+native-tls-devel", rpm:"rust-reqwest+native-tls-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+rustls-tls-devel", rpm:"rust-reqwest+rustls-tls-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+rustls-tls-manual-roots-devel", rpm:"rust-reqwest+rustls-tls-manual-roots-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+rustls-tls-manual-roots-no-provider-devel", rpm:"rust-reqwest+rustls-tls-manual-roots-no-provider-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+rustls-tls-native-roots-devel", rpm:"rust-reqwest+rustls-tls-native-roots-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+rustls-tls-no-provider-devel", rpm:"rust-reqwest+rustls-tls-no-provider-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+rustls-tls-webpki-roots-devel", rpm:"rust-reqwest+rustls-tls-webpki-roots-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+slab-devel", rpm:"rust-reqwest+slab-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+socks-devel", rpm:"rust-reqwest+socks-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+stream-devel", rpm:"rust-reqwest+stream-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+trust-dns-devel", rpm:"rust-reqwest+trust-dns-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest+zstd-devel", rpm:"rust-reqwest+zstd-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest", rpm:"rust-reqwest~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqwest-devel", rpm:"rust-reqwest-devel~0.12.8~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-native-certs+default-devel", rpm:"rust-rustls-native-certs+default-devel~0.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-native-certs", rpm:"rust-rustls-native-certs~0.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-native-certs-devel", rpm:"rust-rustls-native-certs-devel~0.8.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-native-certs0.7+default-devel", rpm:"rust-rustls-native-certs0.7+default-devel~0.7.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-native-certs0.7", rpm:"rust-rustls-native-certs0.7~0.7.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-native-certs0.7-devel", rpm:"rust-rustls-native-certs0.7-devel~0.7.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+channel-devel", rpm:"rust-tonic+channel-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+codegen-devel", rpm:"rust-tonic+codegen-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+default-devel", rpm:"rust-tonic+default-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+gzip-devel", rpm:"rust-tonic+gzip-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+prost-devel", rpm:"rust-tonic+prost-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+router-devel", rpm:"rust-tonic+router-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+server-devel", rpm:"rust-tonic+server-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+tls-devel", rpm:"rust-tonic+tls-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+tls-native-roots-devel", rpm:"rust-tonic+tls-native-roots-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+tls-roots-devel", rpm:"rust-tonic+tls-roots-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+tls-webpki-roots-devel", rpm:"rust-tonic+tls-webpki-roots-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+transport-devel", rpm:"rust-tonic+transport-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic+zstd-devel", rpm:"rust-tonic+zstd-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic", rpm:"rust-tonic~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-build+default-devel", rpm:"rust-tonic-build+default-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-build+prost-build-devel", rpm:"rust-tonic-build+prost-build-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-build+prost-devel", rpm:"rust-tonic-build+prost-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-build+transport-devel", rpm:"rust-tonic-build+transport-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-build", rpm:"rust-tonic-build~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-build-devel", rpm:"rust-tonic-build-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-devel", rpm:"rust-tonic-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-types+default-devel", rpm:"rust-tonic-types+default-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-types", rpm:"rust-tonic-types~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tonic-types-devel", rpm:"rust-tonic-types-devel~0.12.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+__common-devel", rpm:"rust-tower+__common-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+balance-devel", rpm:"rust-tower+balance-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+buffer-devel", rpm:"rust-tower+buffer-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+default-devel", rpm:"rust-tower+default-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+discover-devel", rpm:"rust-tower+discover-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+filter-devel", rpm:"rust-tower+filter-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+full-devel", rpm:"rust-tower+full-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+futures-core-devel", rpm:"rust-tower+futures-core-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+futures-util-devel", rpm:"rust-tower+futures-util-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+hdrhistogram-devel", rpm:"rust-tower+hdrhistogram-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+hedge-devel", rpm:"rust-tower+hedge-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+indexmap-devel", rpm:"rust-tower+indexmap-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+limit-devel", rpm:"rust-tower+limit-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+load-devel", rpm:"rust-tower+load-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+load-shed-devel", rpm:"rust-tower+load-shed-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+log-devel", rpm:"rust-tower+log-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+make-devel", rpm:"rust-tower+make-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+pin-project-lite-devel", rpm:"rust-tower+pin-project-lite-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+ready-cache-devel", rpm:"rust-tower+ready-cache-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+reconnect-devel", rpm:"rust-tower+reconnect-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+retry-devel", rpm:"rust-tower+retry-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+slab-devel", rpm:"rust-tower+slab-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+spawn-ready-devel", rpm:"rust-tower+spawn-ready-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+steer-devel", rpm:"rust-tower+steer-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+sync_wrapper-devel", rpm:"rust-tower+sync_wrapper-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+timeout-devel", rpm:"rust-tower+timeout-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+tokio-devel", rpm:"rust-tower+tokio-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+tokio-stream-devel", rpm:"rust-tower+tokio-stream-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+tokio-util-devel", rpm:"rust-tower+tokio-util-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+tracing-devel", rpm:"rust-tower+tracing-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower+util-devel", rpm:"rust-tower+util-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower", rpm:"rust-tower~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-devel", rpm:"rust-tower-devel~0.5.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+add-extension-devel", rpm:"rust-tower-http+add-extension-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+async-compression-devel", rpm:"rust-tower-http+async-compression-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+auth-devel", rpm:"rust-tower-http+auth-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+base64-devel", rpm:"rust-tower-http+base64-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+catch-panic-devel", rpm:"rust-tower-http+catch-panic-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-br-devel", rpm:"rust-tower-http+compression-br-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-deflate-devel", rpm:"rust-tower-http+compression-deflate-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-full-devel", rpm:"rust-tower-http+compression-full-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-gzip-devel", rpm:"rust-tower-http+compression-gzip-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-zstd-devel", rpm:"rust-tower-http+compression-zstd-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+cors-devel", rpm:"rust-tower-http+cors-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-br-devel", rpm:"rust-tower-http+decompression-br-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-deflate-devel", rpm:"rust-tower-http+decompression-deflate-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-full-devel", rpm:"rust-tower-http+decompression-full-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-gzip-devel", rpm:"rust-tower-http+decompression-gzip-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-zstd-devel", rpm:"rust-tower-http+decompression-zstd-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+default-devel", rpm:"rust-tower-http+default-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+follow-redirect-devel", rpm:"rust-tower-http+follow-redirect-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+fs-devel", rpm:"rust-tower-http+fs-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+full-devel", rpm:"rust-tower-http+full-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+futures-core-devel", rpm:"rust-tower-http+futures-core-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+futures-util-devel", rpm:"rust-tower-http+futures-util-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+httpdate-devel", rpm:"rust-tower-http+httpdate-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+iri-string-devel", rpm:"rust-tower-http+iri-string-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+limit-devel", rpm:"rust-tower-http+limit-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+map-request-body-devel", rpm:"rust-tower-http+map-request-body-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+map-response-body-devel", rpm:"rust-tower-http+map-response-body-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+metrics-devel", rpm:"rust-tower-http+metrics-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+mime-devel", rpm:"rust-tower-http+mime-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+mime_guess-devel", rpm:"rust-tower-http+mime_guess-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+normalize-path-devel", rpm:"rust-tower-http+normalize-path-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+percent-encoding-devel", rpm:"rust-tower-http+percent-encoding-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+propagate-header-devel", rpm:"rust-tower-http+propagate-header-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+redirect-devel", rpm:"rust-tower-http+redirect-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+request-id-devel", rpm:"rust-tower-http+request-id-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+sensitive-headers-devel", rpm:"rust-tower-http+sensitive-headers-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+set-header-devel", rpm:"rust-tower-http+set-header-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+set-status-devel", rpm:"rust-tower-http+set-status-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+timeout-devel", rpm:"rust-tower-http+timeout-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tokio-devel", rpm:"rust-tower-http+tokio-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tokio-util-devel", rpm:"rust-tower-http+tokio-util-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tower-devel", rpm:"rust-tower-http+tower-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+trace-devel", rpm:"rust-tower-http+trace-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tracing-devel", rpm:"rust-tower-http+tracing-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+util-devel", rpm:"rust-tower-http+util-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+uuid-devel", rpm:"rust-tower-http+uuid-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+validate-request-devel", rpm:"rust-tower-http+validate-request-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http", rpm:"rust-tower-http~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http-devel", rpm:"rust-tower-http-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+add-extension-devel", rpm:"rust-tower-http0.5+add-extension-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+async-compression-devel", rpm:"rust-tower-http0.5+async-compression-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+auth-devel", rpm:"rust-tower-http0.5+auth-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+base64-devel", rpm:"rust-tower-http0.5+base64-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+catch-panic-devel", rpm:"rust-tower-http0.5+catch-panic-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+compression-br-devel", rpm:"rust-tower-http0.5+compression-br-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+compression-deflate-devel", rpm:"rust-tower-http0.5+compression-deflate-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+compression-full-devel", rpm:"rust-tower-http0.5+compression-full-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+compression-gzip-devel", rpm:"rust-tower-http0.5+compression-gzip-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+compression-zstd-devel", rpm:"rust-tower-http0.5+compression-zstd-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+cors-devel", rpm:"rust-tower-http0.5+cors-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+decompression-br-devel", rpm:"rust-tower-http0.5+decompression-br-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+decompression-deflate-devel", rpm:"rust-tower-http0.5+decompression-deflate-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+decompression-full-devel", rpm:"rust-tower-http0.5+decompression-full-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+decompression-gzip-devel", rpm:"rust-tower-http0.5+decompression-gzip-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+decompression-zstd-devel", rpm:"rust-tower-http0.5+decompression-zstd-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+default-devel", rpm:"rust-tower-http0.5+default-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+follow-redirect-devel", rpm:"rust-tower-http0.5+follow-redirect-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+fs-devel", rpm:"rust-tower-http0.5+fs-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+full-devel", rpm:"rust-tower-http0.5+full-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+futures-core-devel", rpm:"rust-tower-http0.5+futures-core-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+futures-util-devel", rpm:"rust-tower-http0.5+futures-util-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+httpdate-devel", rpm:"rust-tower-http0.5+httpdate-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+iri-string-devel", rpm:"rust-tower-http0.5+iri-string-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+limit-devel", rpm:"rust-tower-http0.5+limit-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+map-request-body-devel", rpm:"rust-tower-http0.5+map-request-body-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+map-response-body-devel", rpm:"rust-tower-http0.5+map-response-body-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+metrics-devel", rpm:"rust-tower-http0.5+metrics-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+mime-devel", rpm:"rust-tower-http0.5+mime-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+mime_guess-devel", rpm:"rust-tower-http0.5+mime_guess-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+normalize-path-devel", rpm:"rust-tower-http0.5+normalize-path-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+percent-encoding-devel", rpm:"rust-tower-http0.5+percent-encoding-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+propagate-header-devel", rpm:"rust-tower-http0.5+propagate-header-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+redirect-devel", rpm:"rust-tower-http0.5+redirect-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+request-id-devel", rpm:"rust-tower-http0.5+request-id-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+sensitive-headers-devel", rpm:"rust-tower-http0.5+sensitive-headers-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+set-header-devel", rpm:"rust-tower-http0.5+set-header-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+set-status-devel", rpm:"rust-tower-http0.5+set-status-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+timeout-devel", rpm:"rust-tower-http0.5+timeout-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+tokio-devel", rpm:"rust-tower-http0.5+tokio-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+tokio-util-devel", rpm:"rust-tower-http0.5+tokio-util-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+tower-devel", rpm:"rust-tower-http0.5+tower-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+trace-devel", rpm:"rust-tower-http0.5+trace-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+tracing-devel", rpm:"rust-tower-http0.5+tracing-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+util-devel", rpm:"rust-tower-http0.5+util-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+uuid-devel", rpm:"rust-tower-http0.5+uuid-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5+validate-request-devel", rpm:"rust-tower-http0.5+validate-request-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5", rpm:"rust-tower-http0.5~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http0.5-devel", rpm:"rust-tower-http0.5-devel~0.5.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+__common-devel", rpm:"rust-tower0.4+__common-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+balance-devel", rpm:"rust-tower0.4+balance-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+buffer-devel", rpm:"rust-tower0.4+buffer-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+default-devel", rpm:"rust-tower0.4+default-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+discover-devel", rpm:"rust-tower0.4+discover-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+filter-devel", rpm:"rust-tower0.4+filter-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+full-devel", rpm:"rust-tower0.4+full-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+futures-core-devel", rpm:"rust-tower0.4+futures-core-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+futures-util-devel", rpm:"rust-tower0.4+futures-util-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+hdrhistogram-devel", rpm:"rust-tower0.4+hdrhistogram-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+hedge-devel", rpm:"rust-tower0.4+hedge-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+indexmap-devel", rpm:"rust-tower0.4+indexmap-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+limit-devel", rpm:"rust-tower0.4+limit-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+load-devel", rpm:"rust-tower0.4+load-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+load-shed-devel", rpm:"rust-tower0.4+load-shed-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+log-devel", rpm:"rust-tower0.4+log-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+make-devel", rpm:"rust-tower0.4+make-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+pin-project-devel", rpm:"rust-tower0.4+pin-project-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+pin-project-lite-devel", rpm:"rust-tower0.4+pin-project-lite-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+rand-devel", rpm:"rust-tower0.4+rand-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+ready-cache-devel", rpm:"rust-tower0.4+ready-cache-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+reconnect-devel", rpm:"rust-tower0.4+reconnect-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+retry-devel", rpm:"rust-tower0.4+retry-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+slab-devel", rpm:"rust-tower0.4+slab-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+spawn-ready-devel", rpm:"rust-tower0.4+spawn-ready-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+steer-devel", rpm:"rust-tower0.4+steer-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+timeout-devel", rpm:"rust-tower0.4+timeout-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+tokio-devel", rpm:"rust-tower0.4+tokio-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+tokio-stream-devel", rpm:"rust-tower0.4+tokio-stream-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+tokio-util-devel", rpm:"rust-tower0.4+tokio-util-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+tracing-devel", rpm:"rust-tower0.4+tracing-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4+util-devel", rpm:"rust-tower0.4+util-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4", rpm:"rust-tower0.4~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower0.4-devel", rpm:"rust-tower0.4-devel~0.4.13~1.fc41", rls:"FC41"))) {
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
