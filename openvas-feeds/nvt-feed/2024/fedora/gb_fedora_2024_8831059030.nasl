# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.8831059030");
  script_tag(name:"creation_date", value:"2024-10-14 04:08:40 +0000 (Mon, 14 Oct 2024)");
  script_version("2024-10-15T05:05:49+0000");
  script_tag(name:"last_modification", value:"2024-10-15 05:05:49 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-8831059030)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8831059030");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-8831059030");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272914");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272915");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273733");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316061");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-cramjam, rust-async-compression, rust-brotli, rust-brotli-decompressor, rust-libcramjam, rust-libcramjam0.2, rust-nu-command, rust-nu-protocol, rust-tower-http' package(s) announced via the FEDORA-2024-8831059030 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update `rust-brotli-decompressor` to 4.0.1, `rust-brotli` to 7.0.0, and `rust-async-compression` to 0.4.13. Patch dependent packages as needed to avoid compat packages.

----

Rebuild with the latest Rust crate dependency versions, fix automatic provides on Python extension due to SONAME when built with Rust 1.81 or later.");

  script_tag(name:"affected", value:"'python-cramjam, rust-async-compression, rust-brotli, rust-brotli-decompressor, rust-libcramjam, rust-libcramjam0.2, rust-nu-command, rust-nu-protocol, rust-tower-http' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcramjam", rpm:"libcramjam~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcramjam-debuginfo", rpm:"libcramjam-debuginfo~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcramjam-devel", rpm:"libcramjam-devel~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cramjam", rpm:"python-cramjam~2.8.3~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cramjam-debugsource", rpm:"python-cramjam-debugsource~2.8.3~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cramjam", rpm:"python3-cramjam~2.8.3~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cramjam-debuginfo", rpm:"python3-cramjam-debuginfo~2.8.3~8.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+all-algorithms-devel", rpm:"rust-async-compression+all-algorithms-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+all-devel", rpm:"rust-async-compression+all-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+all-implementations-devel", rpm:"rust-async-compression+all-implementations-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+brotli-devel", rpm:"rust-async-compression+brotli-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+bzip2-devel", rpm:"rust-async-compression+bzip2-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+default-devel", rpm:"rust-async-compression+default-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+deflate-devel", rpm:"rust-async-compression+deflate-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+deflate64-devel", rpm:"rust-async-compression+deflate64-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+flate2-devel", rpm:"rust-async-compression+flate2-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+futures-io-devel", rpm:"rust-async-compression+futures-io-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+gzip-devel", rpm:"rust-async-compression+gzip-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+libzstd-devel", rpm:"rust-async-compression+libzstd-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+lzma-devel", rpm:"rust-async-compression+lzma-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+tokio-devel", rpm:"rust-async-compression+tokio-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+xz-devel", rpm:"rust-async-compression+xz-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+xz2-devel", rpm:"rust-async-compression+xz2-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+zlib-devel", rpm:"rust-async-compression+zlib-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+zstd-devel", rpm:"rust-async-compression+zstd-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+zstd-safe-devel", rpm:"rust-async-compression+zstd-safe-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression+zstdmt-devel", rpm:"rust-async-compression+zstdmt-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression", rpm:"rust-async-compression~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-async-compression-devel", rpm:"rust-async-compression-devel~0.4.13~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+alloc-stdlib-devel", rpm:"rust-brotli+alloc-stdlib-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+billing-devel", rpm:"rust-brotli+billing-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+default-devel", rpm:"rust-brotli+default-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+disable-timer-devel", rpm:"rust-brotli+disable-timer-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+disallow_large_window_size-devel", rpm:"rust-brotli+disallow_large_window_size-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+external-literal-probability-devel", rpm:"rust-brotli+external-literal-probability-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+ffi-api-devel", rpm:"rust-brotli+ffi-api-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+float64-devel", rpm:"rust-brotli+float64-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+floating_point_context_mixing-devel", rpm:"rust-brotli+floating_point_context_mixing-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+no-stdlib-ffi-binding-devel", rpm:"rust-brotli+no-stdlib-ffi-binding-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+pass-through-ffi-panics-devel", rpm:"rust-brotli+pass-through-ffi-panics-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+seccomp-devel", rpm:"rust-brotli+seccomp-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+sha2-devel", rpm:"rust-brotli+sha2-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+simd-devel", rpm:"rust-brotli+simd-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+std-devel", rpm:"rust-brotli+std-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+validation-devel", rpm:"rust-brotli+validation-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli+vector_scratch_space-devel", rpm:"rust-brotli+vector_scratch_space-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli", rpm:"rust-brotli~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+alloc-stdlib-devel", rpm:"rust-brotli-decompressor+alloc-stdlib-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+default-devel", rpm:"rust-brotli-decompressor+default-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+disable-timer-devel", rpm:"rust-brotli-decompressor+disable-timer-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+ffi-api-devel", rpm:"rust-brotli-decompressor+ffi-api-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+pass-through-ffi-panics-devel", rpm:"rust-brotli-decompressor+pass-through-ffi-panics-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+seccomp-devel", rpm:"rust-brotli-decompressor+seccomp-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+std-devel", rpm:"rust-brotli-decompressor+std-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor+unsafe-devel", rpm:"rust-brotli-decompressor+unsafe-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor", rpm:"rust-brotli-decompressor~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-decompressor-devel", rpm:"rust-brotli-decompressor-devel~4.0.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-brotli-devel", rpm:"rust-brotli-devel~7.0.0~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam+capi-devel", rpm:"rust-libcramjam+capi-devel~0.3.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam+default-devel", rpm:"rust-libcramjam+default-devel~0.3.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam+libc-devel", rpm:"rust-libcramjam+libc-devel~0.3.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam", rpm:"rust-libcramjam~0.3.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam-devel", rpm:"rust-libcramjam-devel~0.3.0~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam0.2+capi-devel", rpm:"rust-libcramjam0.2+capi-devel~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam0.2+default-devel", rpm:"rust-libcramjam0.2+default-devel~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam0.2+libc-devel", rpm:"rust-libcramjam0.2+libc-devel~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam0.2", rpm:"rust-libcramjam0.2~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam0.2-debugsource", rpm:"rust-libcramjam0.2-debugsource~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-libcramjam0.2-devel", rpm:"rust-libcramjam0.2-devel~0.2.0~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command+default-devel", rpm:"rust-nu-command+default-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command+plugin-devel", rpm:"rust-nu-command+plugin-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command+rusqlite-devel", rpm:"rust-nu-command+rusqlite-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command+sqlite-devel", rpm:"rust-nu-command+sqlite-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command+trash-devel", rpm:"rust-nu-command+trash-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command+trash-support-devel", rpm:"rust-nu-command+trash-support-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command", rpm:"rust-nu-command~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-command-devel", rpm:"rust-nu-command-devel~0.96.1~5.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-protocol+brotli-devel", rpm:"rust-nu-protocol+brotli-devel~0.96.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-protocol+default-devel", rpm:"rust-nu-protocol+default-devel~0.96.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-protocol+plugin-devel", rpm:"rust-nu-protocol+plugin-devel~0.96.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-protocol+rmp-serde-devel", rpm:"rust-nu-protocol+rmp-serde-devel~0.96.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-protocol", rpm:"rust-nu-protocol~0.96.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-nu-protocol-devel", rpm:"rust-nu-protocol-devel~0.96.1~3.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+add-extension-devel", rpm:"rust-tower-http+add-extension-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+async-compression-devel", rpm:"rust-tower-http+async-compression-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+auth-devel", rpm:"rust-tower-http+auth-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+base64-devel", rpm:"rust-tower-http+base64-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+catch-panic-devel", rpm:"rust-tower-http+catch-panic-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-br-devel", rpm:"rust-tower-http+compression-br-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-deflate-devel", rpm:"rust-tower-http+compression-deflate-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-full-devel", rpm:"rust-tower-http+compression-full-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-gzip-devel", rpm:"rust-tower-http+compression-gzip-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+compression-zstd-devel", rpm:"rust-tower-http+compression-zstd-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+cors-devel", rpm:"rust-tower-http+cors-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-br-devel", rpm:"rust-tower-http+decompression-br-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-deflate-devel", rpm:"rust-tower-http+decompression-deflate-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-full-devel", rpm:"rust-tower-http+decompression-full-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-gzip-devel", rpm:"rust-tower-http+decompression-gzip-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+decompression-zstd-devel", rpm:"rust-tower-http+decompression-zstd-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+default-devel", rpm:"rust-tower-http+default-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+follow-redirect-devel", rpm:"rust-tower-http+follow-redirect-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+fs-devel", rpm:"rust-tower-http+fs-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+full-devel", rpm:"rust-tower-http+full-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+futures-core-devel", rpm:"rust-tower-http+futures-core-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+futures-util-devel", rpm:"rust-tower-http+futures-util-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+httpdate-devel", rpm:"rust-tower-http+httpdate-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+iri-string-devel", rpm:"rust-tower-http+iri-string-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+limit-devel", rpm:"rust-tower-http+limit-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+map-request-body-devel", rpm:"rust-tower-http+map-request-body-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+map-response-body-devel", rpm:"rust-tower-http+map-response-body-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+metrics-devel", rpm:"rust-tower-http+metrics-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+mime-devel", rpm:"rust-tower-http+mime-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+mime_guess-devel", rpm:"rust-tower-http+mime_guess-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+normalize-path-devel", rpm:"rust-tower-http+normalize-path-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+percent-encoding-devel", rpm:"rust-tower-http+percent-encoding-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+propagate-header-devel", rpm:"rust-tower-http+propagate-header-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+redirect-devel", rpm:"rust-tower-http+redirect-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+request-id-devel", rpm:"rust-tower-http+request-id-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+sensitive-headers-devel", rpm:"rust-tower-http+sensitive-headers-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+set-header-devel", rpm:"rust-tower-http+set-header-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+set-status-devel", rpm:"rust-tower-http+set-status-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+timeout-devel", rpm:"rust-tower-http+timeout-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tokio-devel", rpm:"rust-tower-http+tokio-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tokio-util-devel", rpm:"rust-tower-http+tokio-util-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tower-devel", rpm:"rust-tower-http+tower-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+trace-devel", rpm:"rust-tower-http+trace-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+tracing-devel", rpm:"rust-tower-http+tracing-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+util-devel", rpm:"rust-tower-http+util-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+uuid-devel", rpm:"rust-tower-http+uuid-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http+validate-request-devel", rpm:"rust-tower-http+validate-request-devel~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http", rpm:"rust-tower-http~0.5.2~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tower-http-devel", rpm:"rust-tower-http-devel~0.5.2~6.fc39", rls:"FC39"))) {
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
