# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.7102483331023101");
  script_cve_id("CVE-2024-47619");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-7f48333f3e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-7f48333f3e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-7f48333f3e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2364863");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'syslog-ng' package(s) announced via the FEDORA-2025-7f48333f3e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 4.8.2 fixing CVE-2024-47619");

  script_tag(name:"affected", value:"'syslog-ng' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng", rpm:"syslog-ng~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-amqp", rpm:"syslog-ng-amqp~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-amqp-debuginfo", rpm:"syslog-ng-amqp-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-bigquery", rpm:"syslog-ng-bigquery~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-bigquery-debuginfo", rpm:"syslog-ng-bigquery-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-bpf", rpm:"syslog-ng-bpf~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-bpf-debuginfo", rpm:"syslog-ng-bpf-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-debuginfo", rpm:"syslog-ng-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-debugsource", rpm:"syslog-ng-debugsource~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-devel", rpm:"syslog-ng-devel~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-geoip", rpm:"syslog-ng-geoip~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-geoip-debuginfo", rpm:"syslog-ng-geoip-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-grpc", rpm:"syslog-ng-grpc~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-grpc-debuginfo", rpm:"syslog-ng-grpc-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-http", rpm:"syslog-ng-http~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-http-debuginfo", rpm:"syslog-ng-http-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-kafka", rpm:"syslog-ng-kafka~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-kafka-debuginfo", rpm:"syslog-ng-kafka-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-libdbi", rpm:"syslog-ng-libdbi~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-libdbi-debuginfo", rpm:"syslog-ng-libdbi-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-loki", rpm:"syslog-ng-loki~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-loki-debuginfo", rpm:"syslog-ng-loki-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-mongodb", rpm:"syslog-ng-mongodb~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-mongodb-debuginfo", rpm:"syslog-ng-mongodb-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-mqtt", rpm:"syslog-ng-mqtt~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-mqtt-debuginfo", rpm:"syslog-ng-mqtt-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-opentelemetry", rpm:"syslog-ng-opentelemetry~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-opentelemetry-debuginfo", rpm:"syslog-ng-opentelemetry-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-python", rpm:"syslog-ng-python~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-python-debuginfo", rpm:"syslog-ng-python-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-python-modules", rpm:"syslog-ng-python-modules~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-redis", rpm:"syslog-ng-redis~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-redis-debuginfo", rpm:"syslog-ng-redis-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-riemann", rpm:"syslog-ng-riemann~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-riemann-debuginfo", rpm:"syslog-ng-riemann-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-slog", rpm:"syslog-ng-slog~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-slog-debuginfo", rpm:"syslog-ng-slog-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-smtp", rpm:"syslog-ng-smtp~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-smtp-debuginfo", rpm:"syslog-ng-smtp-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-snmp", rpm:"syslog-ng-snmp~4.8.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-ng-snmp-debuginfo", rpm:"syslog-ng-snmp-debuginfo~4.8.2~1.fc42", rls:"FC42"))) {
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
