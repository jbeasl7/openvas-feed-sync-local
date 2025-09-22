# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704057");
  script_cve_id("CVE-2017-1000385");
  script_tag(name:"creation_date", value:"2017-12-07 23:00:00 +0000 (Thu, 07 Dec 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-04 18:08:06 +0000 (Thu, 04 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-4057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");

  script_xref(name:"Advisory-ID", value:"DSA-4057-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-4057-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4057");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/erlang");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'erlang' package(s) announced via the DSA-4057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the TLS server in Erlang is vulnerable to an adaptive chosen ciphertext attack against RSA keys.

For the oldstable distribution (jessie), this problem has been fixed in version 1:17.3-dfsg-4+deb8u2.

For the stable distribution (stretch), this problem has been fixed in version 1:19.2.1+dfsg-2+deb9u1.

We recommend that you upgrade your erlang packages.

For the detailed security status of erlang please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'erlang' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-corba", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dbg", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dev", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-doc", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-et", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-examples", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-gs", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ic", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ic-java", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-inets", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mode", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-nox", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-observer", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-percept", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-src", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-test-server", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tools", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-typer", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-webtool", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-wx", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-x11", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:17.3-dfsg-4+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"erlang", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-asn1", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-base-hipe", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-common-test", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-corba", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-crypto", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dbg", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-debugger", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dev", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-dialyzer", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-diameter", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-doc", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-edoc", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eldap", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-erl-docgen", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-et", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-eunit", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-examples", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-gs", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ic", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ic-java", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-inets", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-jinterface", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-manpages", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-megaco", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mnesia", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-mode", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-nox", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-observer", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-odbc", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-os-mon", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-parsetools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-percept", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-public-key", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-reltool", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-runtime-tools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-snmp", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-src", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssh", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-ssl", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-syntax-tools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-tools", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-typer", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-wx", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-x11", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"erlang-xmerl", ver:"1:19.2.1+dfsg-2+deb9u1", rls:"DEB9"))) {
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
