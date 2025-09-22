# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884886");
  script_cve_id("CVE-2023-43669");
  script_tag(name:"creation_date", value:"2023-10-01 01:18:23 +0000 (Sun, 01 Oct 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 15:42:44 +0000 (Mon, 25 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-91a66898d2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-91a66898d2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-91a66898d2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-axum, rust-tokio-tungstenite, rust-tungstenite, rust-warp' package(s) announced via the FEDORA-2023-91a66898d2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the axum crate to version 0.6.20.
- Update the tokio-tungstenite crate to version 0.20.1.
- Update the tungstenite crate to version 0.20.1.
- Port warp from tungstenite v0.18 to v0.20.

Version 0.20.1 of the tungstenite crate includes a fix for CVE-2023-43669. No dependent applications need to be rebuilt since none of them use the WebSocket functionality of axum or warp.");

  script_tag(name:"affected", value:"'rust-axum, rust-tokio-tungstenite, rust-tungstenite, rust-warp' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+default-devel", rpm:"rust-axum+default-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+form-devel", rpm:"rust-axum+form-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+headers-devel", rpm:"rust-axum+headers-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+http1-devel", rpm:"rust-axum+http1-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+http2-devel", rpm:"rust-axum+http2-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+json-devel", rpm:"rust-axum+json-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+macros-devel", rpm:"rust-axum+macros-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+matched-path-devel", rpm:"rust-axum+matched-path-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+multipart-devel", rpm:"rust-axum+multipart-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+original-uri-devel", rpm:"rust-axum+original-uri-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+query-devel", rpm:"rust-axum+query-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+tokio-devel", rpm:"rust-axum+tokio-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+tower-http-devel", rpm:"rust-axum+tower-http-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+tower-log-devel", rpm:"rust-axum+tower-log-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+tracing-devel", rpm:"rust-axum+tracing-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum+ws-devel", rpm:"rust-axum+ws-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum", rpm:"rust-axum~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-axum-devel", rpm:"rust-axum-devel~0.6.20~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+connect-devel", rpm:"rust-tokio-tungstenite+connect-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+default-devel", rpm:"rust-tokio-tungstenite+default-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+handshake-devel", rpm:"rust-tokio-tungstenite+handshake-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+native-tls-crate-devel", rpm:"rust-tokio-tungstenite+native-tls-crate-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+native-tls-devel", rpm:"rust-tokio-tungstenite+native-tls-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+stream-devel", rpm:"rust-tokio-tungstenite+stream-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite+tokio-native-tls-devel", rpm:"rust-tokio-tungstenite+tokio-native-tls-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite", rpm:"rust-tokio-tungstenite~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tokio-tungstenite-devel", rpm:"rust-tokio-tungstenite-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+data-encoding-devel", rpm:"rust-tungstenite+data-encoding-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+default-devel", rpm:"rust-tungstenite+default-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+handshake-devel", rpm:"rust-tungstenite+handshake-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+http-devel", rpm:"rust-tungstenite+http-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+httparse-devel", rpm:"rust-tungstenite+httparse-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+native-tls-crate-devel", rpm:"rust-tungstenite+native-tls-crate-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+native-tls-devel", rpm:"rust-tungstenite+native-tls-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+sha1-devel", rpm:"rust-tungstenite+sha1-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite+url-devel", rpm:"rust-tungstenite+url-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite", rpm:"rust-tungstenite~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tungstenite-devel", rpm:"rust-tungstenite-devel~0.20.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+async-compression-devel", rpm:"rust-warp+async-compression-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+compression-brotli-devel", rpm:"rust-warp+compression-brotli-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+compression-devel", rpm:"rust-warp+compression-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+compression-gzip-devel", rpm:"rust-warp+compression-gzip-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+default-devel", rpm:"rust-warp+default-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+multer-devel", rpm:"rust-warp+multer-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+multipart-devel", rpm:"rust-warp+multipart-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+tokio-tungstenite-devel", rpm:"rust-warp+tokio-tungstenite-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp+websocket-devel", rpm:"rust-warp+websocket-devel~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp", rpm:"rust-warp~0.3.5~6.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-warp-devel", rpm:"rust-warp-devel~0.3.5~6.fc39", rls:"FC39"))) {
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
