# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1971991008524");
  script_cve_id("CVE-2026-25554");
  script_tag(name:"creation_date", value:"2026-03-06 04:36:09 +0000 (Fri, 06 Mar 2026)");
  script_version("2026-03-06T15:49:04+0000");
  script_tag(name:"last_modification", value:"2026-03-06 15:49:04 +0000 (Fri, 06 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-27 19:16:07 +0000 (Fri, 27 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-1a199d8524)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-1a199d8524");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-1a199d8524");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442706");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensips' package(s) announced via the FEDORA-2026-1a199d8524 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix CVE-2026-25554");

  script_tag(name:"affected", value:"'opensips' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensips", rpm:"opensips~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-aaa_diameter", rpm:"opensips-aaa_diameter~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-aaa_diameter-debuginfo", rpm:"opensips-aaa_diameter-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-aaa_radius", rpm:"opensips-aaa_radius~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-aaa_radius-debuginfo", rpm:"opensips-aaa_radius-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-acc", rpm:"opensips-acc~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-acc-debuginfo", rpm:"opensips-acc-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-aka_av_diameter", rpm:"opensips-aka_av_diameter~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-aka_av_diameter-debuginfo", rpm:"opensips-aka_av_diameter-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-auth_aaa", rpm:"opensips-auth_aaa~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-auth_aaa-debuginfo", rpm:"opensips-auth_aaa-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-auth_jwt", rpm:"opensips-auth_jwt~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-auth_jwt-debuginfo", rpm:"opensips-auth_jwt-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-b2bua", rpm:"opensips-b2bua~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-b2bua-debuginfo", rpm:"opensips-b2bua-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_couchbase", rpm:"opensips-cachedb_couchbase~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_couchbase-debuginfo", rpm:"opensips-cachedb_couchbase-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_memcached", rpm:"opensips-cachedb_memcached~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_memcached-debuginfo", rpm:"opensips-cachedb_memcached-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_mongodb", rpm:"opensips-cachedb_mongodb~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_mongodb-debuginfo", rpm:"opensips-cachedb_mongodb-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_redis", rpm:"opensips-cachedb_redis~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cachedb_redis-debuginfo", rpm:"opensips-cachedb_redis-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-call_center", rpm:"opensips-call_center~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-call_center-debuginfo", rpm:"opensips-call_center-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-carrierroute", rpm:"opensips-carrierroute~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-carrierroute-debuginfo", rpm:"opensips-carrierroute-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cgrates", rpm:"opensips-cgrates~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cgrates-debuginfo", rpm:"opensips-cgrates-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-compression", rpm:"opensips-compression~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-compression-debuginfo", rpm:"opensips-compression-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cpl_c", rpm:"opensips-cpl_c~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-cpl_c-debuginfo", rpm:"opensips-cpl_c-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_berkeley", rpm:"opensips-db_berkeley~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_berkeley-debuginfo", rpm:"opensips-db_berkeley-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_http", rpm:"opensips-db_http~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_http-debuginfo", rpm:"opensips-db_http-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_mysql", rpm:"opensips-db_mysql~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_mysql-debuginfo", rpm:"opensips-db_mysql-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_perlvdb", rpm:"opensips-db_perlvdb~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_perlvdb-debuginfo", rpm:"opensips-db_perlvdb-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_postgresql", rpm:"opensips-db_postgresql~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_postgresql-debuginfo", rpm:"opensips-db_postgresql-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_sqlite", rpm:"opensips-db_sqlite~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_sqlite-debuginfo", rpm:"opensips-db_sqlite-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_unixodbc", rpm:"opensips-db_unixodbc~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-db_unixodbc-debuginfo", rpm:"opensips-db_unixodbc-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-debuginfo", rpm:"opensips-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-debugsource", rpm:"opensips-debugsource~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-emergency", rpm:"opensips-emergency~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-emergency-debuginfo", rpm:"opensips-emergency-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-event_kafka", rpm:"opensips-event_kafka~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-event_kafka-debuginfo", rpm:"opensips-event_kafka-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-event_rabbitmq", rpm:"opensips-event_rabbitmq~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-event_rabbitmq-debuginfo", rpm:"opensips-event_rabbitmq-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-h350", rpm:"opensips-h350~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-h350-debuginfo", rpm:"opensips-h350-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-http2d", rpm:"opensips-http2d~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-http2d-debuginfo", rpm:"opensips-http2d-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-httpd", rpm:"opensips-httpd~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-httpd-debuginfo", rpm:"opensips-httpd-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-identity", rpm:"opensips-identity~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-identity-debuginfo", rpm:"opensips-identity-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-jabber", rpm:"opensips-jabber~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-jabber-debuginfo", rpm:"opensips-jabber-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-json", rpm:"opensips-json~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-json-debuginfo", rpm:"opensips-json-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-ldap", rpm:"opensips-ldap~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-ldap-debuginfo", rpm:"opensips-ldap-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-lua", rpm:"opensips-lua~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-lua-debuginfo", rpm:"opensips-lua-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-media_exchange", rpm:"opensips-media_exchange~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-media_exchange-debuginfo", rpm:"opensips-media_exchange-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mi_html", rpm:"opensips-mi_html~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mi_html-debuginfo", rpm:"opensips-mi_html-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mi_http", rpm:"opensips-mi_http~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mi_http-debuginfo", rpm:"opensips-mi_http-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mi_xmlrpc_ng", rpm:"opensips-mi_xmlrpc_ng~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mi_xmlrpc_ng-debuginfo", rpm:"opensips-mi_xmlrpc_ng-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mmgeoip", rpm:"opensips-mmgeoip~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-mmgeoip-debuginfo", rpm:"opensips-mmgeoip-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-msrp", rpm:"opensips-msrp~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-msrp-debuginfo", rpm:"opensips-msrp-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-peering", rpm:"opensips-peering~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-peering-debuginfo", rpm:"opensips-peering-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-perl", rpm:"opensips-perl~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-perl-debuginfo", rpm:"opensips-perl-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pi_http", rpm:"opensips-pi_http~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pi_http-debuginfo", rpm:"opensips-pi_http-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence", rpm:"opensips-presence~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence-debuginfo", rpm:"opensips-presence-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_callinfo", rpm:"opensips-presence_callinfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_callinfo-debuginfo", rpm:"opensips-presence_callinfo-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_dfks", rpm:"opensips-presence_dfks~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_dfks-debuginfo", rpm:"opensips-presence_dfks-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_dialoginfo", rpm:"opensips-presence_dialoginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_dialoginfo-debuginfo", rpm:"opensips-presence_dialoginfo-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_mwi", rpm:"opensips-presence_mwi~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_mwi-debuginfo", rpm:"opensips-presence_mwi-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_reginfo", rpm:"opensips-presence_reginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_reginfo-debuginfo", rpm:"opensips-presence_reginfo-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_xcapdiff", rpm:"opensips-presence_xcapdiff~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_xcapdiff-debuginfo", rpm:"opensips-presence_xcapdiff-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_xml", rpm:"opensips-presence_xml~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-presence_xml-debuginfo", rpm:"opensips-presence_xml-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-prometheus", rpm:"opensips-prometheus~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-prometheus-debuginfo", rpm:"opensips-prometheus-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_bins", rpm:"opensips-proto_bins~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_bins-debuginfo", rpm:"opensips-proto_bins-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_ipsec", rpm:"opensips-proto_ipsec~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_ipsec-debuginfo", rpm:"opensips-proto_ipsec-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_sctp", rpm:"opensips-proto_sctp~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_sctp-debuginfo", rpm:"opensips-proto_sctp-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_tls", rpm:"opensips-proto_tls~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_tls-debuginfo", rpm:"opensips-proto_tls-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_wss", rpm:"opensips-proto_wss~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-proto_wss-debuginfo", rpm:"opensips-proto_wss-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua", rpm:"opensips-pua~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua-debuginfo", rpm:"opensips-pua-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_bla", rpm:"opensips-pua_bla~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_bla-debuginfo", rpm:"opensips-pua_bla-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_dialoginfo", rpm:"opensips-pua_dialoginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_dialoginfo-debuginfo", rpm:"opensips-pua_dialoginfo-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_mi", rpm:"opensips-pua_mi~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_mi-debuginfo", rpm:"opensips-pua_mi-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_reginfo", rpm:"opensips-pua_reginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_reginfo-debuginfo", rpm:"opensips-pua_reginfo-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_usrloc", rpm:"opensips-pua_usrloc~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_usrloc-debuginfo", rpm:"opensips-pua_usrloc-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_xmpp", rpm:"opensips-pua_xmpp~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-pua_xmpp-debuginfo", rpm:"opensips-pua_xmpp-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rabbitmq", rpm:"opensips-rabbitmq~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rabbitmq-debuginfo", rpm:"opensips-rabbitmq-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rabbitmq_consumer", rpm:"opensips-rabbitmq_consumer~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rabbitmq_consumer-debuginfo", rpm:"opensips-rabbitmq_consumer-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-regex", rpm:"opensips-regex~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-regex-debuginfo", rpm:"opensips-regex-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rest_client", rpm:"opensips-rest_client~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rest_client-debuginfo", rpm:"opensips-rest_client-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rls", rpm:"opensips-rls~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-rls-debuginfo", rpm:"opensips-rls-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-siprec", rpm:"opensips-siprec~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-siprec-debuginfo", rpm:"opensips-siprec-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-snmpstats", rpm:"opensips-snmpstats~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-snmpstats-debuginfo", rpm:"opensips-snmpstats-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-stir_shaken", rpm:"opensips-stir_shaken~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-stir_shaken-debuginfo", rpm:"opensips-stir_shaken-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-tls_mgm", rpm:"opensips-tls_mgm~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-tls_mgm-debuginfo", rpm:"opensips-tls_mgm-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-tls_openssl", rpm:"opensips-tls_openssl~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-tls_openssl-debuginfo", rpm:"opensips-tls_openssl-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-uuid", rpm:"opensips-uuid~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-uuid-debuginfo", rpm:"opensips-uuid-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xcap", rpm:"opensips-xcap~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xcap-debuginfo", rpm:"opensips-xcap-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xcap_client", rpm:"opensips-xcap_client~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xcap_client-debuginfo", rpm:"opensips-xcap_client-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xml", rpm:"opensips-xml~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xml-debuginfo", rpm:"opensips-xml-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xmpp", rpm:"opensips-xmpp~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensips-xmpp-debuginfo", rpm:"opensips-xmpp-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-opensips", rpm:"python3-opensips~3.5.9~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-opensips-debuginfo", rpm:"python3-opensips-debuginfo~3.5.9~2.fc42", rls:"FC42"))) {
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
