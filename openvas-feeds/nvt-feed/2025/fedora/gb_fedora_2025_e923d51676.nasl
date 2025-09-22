# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10192310051676");
  script_tag(name:"creation_date", value:"2025-04-21 04:05:10 +0000 (Mon, 21 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-e923d51676)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-e923d51676");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-e923d51676");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2277901");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291175");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2323618");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2324926");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352783");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358015");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358018");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358020");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358105");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358292");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358507");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358521");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358522");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358527");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358606");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358642");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/blob/0.6.14/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/zip-rs/zip2/security/advisories/GHSA-94vh-gphv-8pm8");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2024-0421.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pydantic-core, rust-adblock, rust-cookie_store, rust-gitui, rust-gstreamer, rust-icu_collections, rust-icu_locid, rust-icu_locid_transform, rust-icu_locid_transform_data, rust-icu_normalizer, rust-icu_normalizer_data, rust-icu_properties, rust-icu_properties_data, rust-icu_provider, rust-icu_provider_macros, rust-idna, rust-idna_adapter, rust-litemap, rust-ron, rust-sequoia-openpgp, rust-sequoia-openpgp1, rust-tinystr, rust-url, rust-utf16_iter, rust-version-ranges, rust-write16, rust-writeable, rust-zerovec, rust-zip, uv' package(s) announced via the FEDORA-2025-e923d51676 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update uv to 0.6.14, with [various bugfixes and new features]([link moved to references]).

Update rust-idna to 1.0.3 (fixing [RUSTSEC-2024-0421]([link moved to references])), rust-url to 2.5.4, rust-adblock to 0.9.6, and rust-cookie_store to 0.21.1, adjust some reverse dependencies of rust-idna. Initial packages for many dependencies.

Update rust-ron to 0.9.

Update rust-zip to 2.6.1, fixing [GHSA-94vh-gphv-8pm8]([link moved to references]).");

  script_tag(name:"affected", value:"'python-pydantic-core, rust-adblock, rust-cookie_store, rust-gitui, rust-gstreamer, rust-icu_collections, rust-icu_locid, rust-icu_locid_transform, rust-icu_locid_transform_data, rust-icu_normalizer, rust-icu_normalizer_data, rust-icu_properties, rust-icu_properties_data, rust-icu_provider, rust-icu_provider_macros, rust-idna, rust-idna_adapter, rust-litemap, rust-ron, rust-sequoia-openpgp, rust-sequoia-openpgp1, rust-tinystr, rust-url, rust-utf16_iter, rust-version-ranges, rust-write16, rust-writeable, rust-zerovec, rust-zip, uv' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"gitui", rpm:"gitui~0.26.3~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitui-debuginfo", rpm:"gitui-debuginfo~0.26.3~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic-core", rpm:"python-pydantic-core~2.20.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic-core-debugsource", rpm:"python-pydantic-core-debugsource~2.20.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-core", rpm:"python3-pydantic-core~2.20.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-core-debuginfo", rpm:"python3-pydantic-core-debuginfo~2.20.1~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.6.14~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+addr-devel", rpm:"rust-adblock+addr-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+content-blocking-devel", rpm:"rust-adblock+content-blocking-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+default-devel", rpm:"rust-adblock+default-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+embedded-domain-resolver-devel", rpm:"rust-adblock+embedded-domain-resolver-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+full-regex-handling-devel", rpm:"rust-adblock+full-regex-handling-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+lifeguard-devel", rpm:"rust-adblock+lifeguard-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+object-pooling-devel", rpm:"rust-adblock+object-pooling-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+regex-debug-info-devel", rpm:"rust-adblock+regex-debug-info-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+resource-assembler-devel", rpm:"rust-adblock+resource-assembler-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock+unsync-regex-caching-devel", rpm:"rust-adblock+unsync-regex-caching-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock", rpm:"rust-adblock~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-adblock-devel", rpm:"rust-adblock-devel~0.9.6~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+default-devel", rpm:"rust-cookie_store+default-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+log_secure_cookie_values-devel", rpm:"rust-cookie_store+log_secure_cookie_values-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+preserve_order-devel", rpm:"rust-cookie_store+preserve_order-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+public_suffix-devel", rpm:"rust-cookie_store+public_suffix-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+serde-devel", rpm:"rust-cookie_store+serde-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+serde_json-devel", rpm:"rust-cookie_store+serde_json-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store+serde_ron-devel", rpm:"rust-cookie_store+serde_ron-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store", rpm:"rust-cookie_store~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cookie_store-devel", rpm:"rust-cookie_store-devel~0.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui", rpm:"rust-gitui~0.26.3~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui-debugsource", rpm:"rust-gitui-debugsource~0.26.3~6.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+default-devel", rpm:"rust-gstreamer+default-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+log-devel", rpm:"rust-gstreamer+log-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+serde-devel", rpm:"rust-gstreamer+serde-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+serde_bytes-devel", rpm:"rust-gstreamer+serde_bytes-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_16-devel", rpm:"rust-gstreamer+v1_16-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_18-devel", rpm:"rust-gstreamer+v1_18-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_20-devel", rpm:"rust-gstreamer+v1_20-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_22-devel", rpm:"rust-gstreamer+v1_22-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_24-devel", rpm:"rust-gstreamer+v1_24-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer", rpm:"rust-gstreamer~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer-devel", rpm:"rust-gstreamer-devel~0.23.5~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_collections+databake-devel", rpm:"rust-icu_collections+databake-devel~1.5.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_collections+default-devel", rpm:"rust-icu_collections+default-devel~1.5.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_collections+serde-devel", rpm:"rust-icu_collections+serde-devel~1.5.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_collections+std-devel", rpm:"rust-icu_collections+std-devel~1.5.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_collections", rpm:"rust-icu_collections~1.5.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_collections-devel", rpm:"rust-icu_collections-devel~1.5.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid+databake-devel", rpm:"rust-icu_locid+databake-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid+default-devel", rpm:"rust-icu_locid+default-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid+serde-devel", rpm:"rust-icu_locid+serde-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid+std-devel", rpm:"rust-icu_locid+std-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid+zerovec-devel", rpm:"rust-icu_locid+zerovec-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid", rpm:"rust-icu_locid~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid-devel", rpm:"rust-icu_locid-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform+compiled_data-devel", rpm:"rust-icu_locid_transform+compiled_data-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform+datagen-devel", rpm:"rust-icu_locid_transform+datagen-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform+default-devel", rpm:"rust-icu_locid_transform+default-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform+serde-devel", rpm:"rust-icu_locid_transform+serde-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform+std-devel", rpm:"rust-icu_locid_transform+std-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform", rpm:"rust-icu_locid_transform~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform-devel", rpm:"rust-icu_locid_transform-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform_data+default-devel", rpm:"rust-icu_locid_transform_data+default-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform_data", rpm:"rust-icu_locid_transform_data~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_locid_transform_data-devel", rpm:"rust-icu_locid_transform_data-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer+compiled_data-devel", rpm:"rust-icu_normalizer+compiled_data-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer+datagen-devel", rpm:"rust-icu_normalizer+datagen-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer+default-devel", rpm:"rust-icu_normalizer+default-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer+experimental-devel", rpm:"rust-icu_normalizer+experimental-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer+serde-devel", rpm:"rust-icu_normalizer+serde-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer+std-devel", rpm:"rust-icu_normalizer+std-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer", rpm:"rust-icu_normalizer~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer-devel", rpm:"rust-icu_normalizer-devel~1.5.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer_data+default-devel", rpm:"rust-icu_normalizer_data+default-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer_data", rpm:"rust-icu_normalizer_data~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_normalizer_data-devel", rpm:"rust-icu_normalizer_data-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties+bidi-devel", rpm:"rust-icu_properties+bidi-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties+compiled_data-devel", rpm:"rust-icu_properties+compiled_data-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties+datagen-devel", rpm:"rust-icu_properties+datagen-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties+default-devel", rpm:"rust-icu_properties+default-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties+serde-devel", rpm:"rust-icu_properties+serde-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties+std-devel", rpm:"rust-icu_properties+std-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties", rpm:"rust-icu_properties~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties-devel", rpm:"rust-icu_properties-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties_data+default-devel", rpm:"rust-icu_properties_data+default-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties_data", rpm:"rust-icu_properties_data~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_properties_data-devel", rpm:"rust-icu_properties_data-devel~1.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+datagen-devel", rpm:"rust-icu_provider+datagen-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+default-devel", rpm:"rust-icu_provider+default-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+deserialize_bincode_1-devel", rpm:"rust-icu_provider+deserialize_bincode_1-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+deserialize_json-devel", rpm:"rust-icu_provider+deserialize_json-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+experimental-devel", rpm:"rust-icu_provider+experimental-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+log_error_context-devel", rpm:"rust-icu_provider+log_error_context-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+logging-devel", rpm:"rust-icu_provider+logging-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+macros-devel", rpm:"rust-icu_provider+macros-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+serde-devel", rpm:"rust-icu_provider+serde-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+std-devel", rpm:"rust-icu_provider+std-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider+sync-devel", rpm:"rust-icu_provider+sync-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider", rpm:"rust-icu_provider~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider-devel", rpm:"rust-icu_provider-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider_macros+default-devel", rpm:"rust-icu_provider_macros+default-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider_macros", rpm:"rust-icu_provider_macros~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-icu_provider_macros-devel", rpm:"rust-icu_provider_macros-devel~1.5.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna+alloc-devel", rpm:"rust-idna+alloc-devel~1.0.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna+compiled_data-devel", rpm:"rust-idna+compiled_data-devel~1.0.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna+default-devel", rpm:"rust-idna+default-devel~1.0.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna+std-devel", rpm:"rust-idna+std-devel~1.0.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna", rpm:"rust-idna~1.0.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna-devel", rpm:"rust-idna-devel~1.0.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna_adapter+compiled_data-devel", rpm:"rust-idna_adapter+compiled_data-devel~1.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna_adapter+default-devel", rpm:"rust-idna_adapter+default-devel~1.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna_adapter", rpm:"rust-idna_adapter~1.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-idna_adapter-devel", rpm:"rust-idna_adapter-devel~1.2.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap+alloc-devel", rpm:"rust-litemap+alloc-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap+databake-devel", rpm:"rust-litemap+databake-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap+default-devel", rpm:"rust-litemap+default-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap+serde-devel", rpm:"rust-litemap+serde-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap+testing-devel", rpm:"rust-litemap+testing-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap+yoke-devel", rpm:"rust-litemap+yoke-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap", rpm:"rust-litemap~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-litemap-devel", rpm:"rust-litemap-devel~0.7.3~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron+default-devel", rpm:"rust-ron+default-devel~0.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron+indexmap-devel", rpm:"rust-ron+indexmap-devel~0.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron+integer128-devel", rpm:"rust-ron+integer128-devel~0.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron", rpm:"rust-ron~0.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron-devel", rpm:"rust-ron-devel~0.9.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+__implicit-crypto-backend-for-tests-devel", rpm:"rust-sequoia-openpgp+__implicit-crypto-backend-for-tests-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+allow-experimental-crypto-devel", rpm:"rust-sequoia-openpgp+allow-experimental-crypto-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+allow-variable-time-crypto-devel", rpm:"rust-sequoia-openpgp+allow-variable-time-crypto-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+compression-bzip2-devel", rpm:"rust-sequoia-openpgp+compression-bzip2-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+compression-deflate-devel", rpm:"rust-sequoia-openpgp+compression-deflate-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+compression-devel", rpm:"rust-sequoia-openpgp+compression-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+crypto-nettle-devel", rpm:"rust-sequoia-openpgp+crypto-nettle-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+crypto-openssl-devel", rpm:"rust-sequoia-openpgp+crypto-openssl-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+crypto-rust-devel", rpm:"rust-sequoia-openpgp+crypto-rust-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+default-devel", rpm:"rust-sequoia-openpgp+default-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp", rpm:"rust-sequoia-openpgp~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp-devel", rpm:"rust-sequoia-openpgp-devel~2.0.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+__implicit-crypto-backend-for-tests-devel", rpm:"rust-sequoia-openpgp1+__implicit-crypto-backend-for-tests-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+allow-experimental-crypto-devel", rpm:"rust-sequoia-openpgp1+allow-experimental-crypto-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+allow-variable-time-crypto-devel", rpm:"rust-sequoia-openpgp1+allow-variable-time-crypto-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+compression-bzip2-devel", rpm:"rust-sequoia-openpgp1+compression-bzip2-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+compression-deflate-devel", rpm:"rust-sequoia-openpgp1+compression-deflate-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+compression-devel", rpm:"rust-sequoia-openpgp1+compression-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+crypto-nettle-devel", rpm:"rust-sequoia-openpgp1+crypto-nettle-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+crypto-openssl-devel", rpm:"rust-sequoia-openpgp1+crypto-openssl-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+crypto-rust-devel", rpm:"rust-sequoia-openpgp1+crypto-rust-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1+default-devel", rpm:"rust-sequoia-openpgp1+default-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1", rpm:"rust-sequoia-openpgp1~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp1-devel", rpm:"rust-sequoia-openpgp1-devel~1.22.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr+alloc-devel", rpm:"rust-tinystr+alloc-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr+databake-devel", rpm:"rust-tinystr+databake-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr+default-devel", rpm:"rust-tinystr+default-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr+serde-devel", rpm:"rust-tinystr+serde-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr+std-devel", rpm:"rust-tinystr+std-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr+zerovec-devel", rpm:"rust-tinystr+zerovec-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr", rpm:"rust-tinystr~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tinystr-devel", rpm:"rust-tinystr-devel~0.7.6~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-url+default-devel", rpm:"rust-url+default-devel~2.5.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-url+expose_internals-devel", rpm:"rust-url+expose_internals-devel~2.5.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-url+serde-devel", rpm:"rust-url+serde-devel~2.5.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-url+std-devel", rpm:"rust-url+std-devel~2.5.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-url", rpm:"rust-url~2.5.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-url-devel", rpm:"rust-url-devel~2.5.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-utf16_iter+default-devel", rpm:"rust-utf16_iter+default-devel~1.0.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-utf16_iter", rpm:"rust-utf16_iter~1.0.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-utf16_iter-devel", rpm:"rust-utf16_iter-devel~1.0.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges+default-devel", rpm:"rust-version-ranges+default-devel~0.1.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges+proptest-devel", rpm:"rust-version-ranges+proptest-devel~0.1.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges+serde-devel", rpm:"rust-version-ranges+serde-devel~0.1.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges", rpm:"rust-version-ranges~0.1.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges-devel", rpm:"rust-version-ranges-devel~0.1.1~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-write16+alloc-devel", rpm:"rust-write16+alloc-devel~1.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-write16+arrayvec-devel", rpm:"rust-write16+arrayvec-devel~1.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-write16+default-devel", rpm:"rust-write16+default-devel~1.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-write16+smallvec-devel", rpm:"rust-write16+smallvec-devel~1.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-write16", rpm:"rust-write16~1.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-write16-devel", rpm:"rust-write16-devel~1.0.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-writeable+default-devel", rpm:"rust-writeable+default-devel~0.5.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-writeable+either-devel", rpm:"rust-writeable+either-devel~0.5.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-writeable", rpm:"rust-writeable~0.5.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-writeable-devel", rpm:"rust-writeable-devel~0.5.5~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+databake-devel", rpm:"rust-zerovec+databake-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+default-devel", rpm:"rust-zerovec+default-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+derive-devel", rpm:"rust-zerovec+derive-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+hashmap-devel", rpm:"rust-zerovec+hashmap-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+serde-devel", rpm:"rust-zerovec+serde-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+std-devel", rpm:"rust-zerovec+std-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec+yoke-devel", rpm:"rust-zerovec+yoke-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec", rpm:"rust-zerovec~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zerovec-devel", rpm:"rust-zerovec-devel~0.10.4~4.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+_all-features-devel", rpm:"rust-zip+_all-features-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+_deflate-any-devel", rpm:"rust-zip+_deflate-any-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+aes-crypto-devel", rpm:"rust-zip+aes-crypto-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+aes-devel", rpm:"rust-zip+aes-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+bzip2-devel", rpm:"rust-zip+bzip2-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+chrono-devel", rpm:"rust-zip+chrono-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+constant_time_eq-devel", rpm:"rust-zip+constant_time_eq-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+default-devel", rpm:"rust-zip+default-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-devel", rpm:"rust-zip+deflate-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-flate2-devel", rpm:"rust-zip+deflate-flate2-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-miniz-devel", rpm:"rust-zip+deflate-miniz-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-zlib-devel", rpm:"rust-zip+deflate-zlib-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-zlib-ng-devel", rpm:"rust-zip+deflate-zlib-ng-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-zopfli-devel", rpm:"rust-zip+deflate-zopfli-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate64-devel", rpm:"rust-zip+deflate64-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+flate2-devel", rpm:"rust-zip+flate2-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+getrandom-devel", rpm:"rust-zip+getrandom-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+hmac-devel", rpm:"rust-zip+hmac-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+jiff-02-devel", rpm:"rust-zip+jiff-02-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+lzma-devel", rpm:"rust-zip+lzma-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+lzma-rs-devel", rpm:"rust-zip+lzma-rs-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+pbkdf2-devel", rpm:"rust-zip+pbkdf2-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+proc-macro2-devel", rpm:"rust-zip+proc-macro2-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+sha1-devel", rpm:"rust-zip+sha1-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+time-devel", rpm:"rust-zip+time-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+unreserved-devel", rpm:"rust-zip+unreserved-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+xz-devel", rpm:"rust-zip+xz-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+zeroize-devel", rpm:"rust-zip+zeroize-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+zopfli-devel", rpm:"rust-zip+zopfli-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+zstd-devel", rpm:"rust-zip+zstd-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip", rpm:"rust-zip~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip-devel", rpm:"rust-zip-devel~2.6.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.6.14~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.6.14~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.6.14~3.fc40", rls:"FC40"))) {
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
