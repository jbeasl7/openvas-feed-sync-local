# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

# @brief Returns a list of known VMware Spring Framework components.
#
# @return A list of known VMware Spring Framework components.
#
function spring_framework_comp_list() {

  local_var comp_list;

  comp_list = make_list(

    # nb: The list should be always sorted in a way that e.g. "actuator-autoconfigure" is included
    # before "actuator". Otherwise the detection VTs using this in e.g. a regex would extract the
    # wrong component name as the less specific one.

    # The "org.springframework.*" ones from https://github.com/spring-projects/spring-framework/tree/3.0.x
    # but without the "org.springframework" and the "." in the component name replaced by "-".
    # These have been cross-verified against the ones from https://packages.debian.org/search?keywords=libspring
    "aop",
    "asm",
    "aspects",
    "beans",
    "context-support",
    "context",
    "core",
    "expression",
    "instrument-tomcat",
    "instrument",
    "integration-tests",
    "jdbc",
    "jms",
    "orm",
    "oxm",
    "spring-library",
    "spring-parent",
    "test",
    "transaction",
    "web-portlet",
    "web-servlet",
    "web-struts",
    "web",
    # And the spring-* ones from https://github.com/spring-projects/spring-framework/tree/5.3.x
    # but without the "spring-" prefix. Note that a few are shared across both lists.
    "aop",
    "aspects",
    "beans",
    "context-indexer",
    "context-support",
    "context",
    "core",
    "expression",
    "instrument",
    "jcl",
    "jdbc",
    "jms",
    "messaging",
    "orm",
    "oxm",
    "r2dbc",
    "test",
    "tx",
    "webflux",
    "webmvc",
    "websocket",
    "web" );

  comp_list = make_list_unique( comp_list );

  return comp_list;
}

# @brief Returns a list of known VMware Spring Boot components.
#
# @note This list doesn't contain the "core" Spring Boot name as it isn't name like this as opposite
#       to the Spring Framework. This needs to be handled separately in the calling VT.
#
# @return A list of known VMware Spring Boot components.
#
function spring_boot_comp_list() {

  local_var comp_list;

  comp_list = make_list(

    # nb: The list should be always sorted in a way that e.g. "actuator-autoconfigure" is included
    # before "actuator". Otherwise the detection VTs using this in e.g. a regex would extract the
    # wrong component name as the less specific one.

    # All of https://github.com/spring-projects/spring-boot/tree/2.7.x/spring-boot-project but
    # without the "spring-boot" prefix. Note that "spring-boot-starters" and "spring-boot-tools"
    # have sub-folders and only the sub-folders below are included later.
    "actuator-autoconfigure",
    "actuator",
    "autoconfigure",
    "cli",
    "dependencies",
    "devtools",
    "docs",
    "parent",
    "properties-migrator",
    "test-autoconfigure",
    "test",
    # From https://github.com/spring-projects/spring-boot/tree/2.7.x/spring-boot-project/spring-boot-starters
    "starter-actuator",
    "starter-amqp",
    "starter-aop",
    "starter-artemis",
    "starter-batch",
    "starter-cache",
    "starter-data-cassandra-reactive",
    "starter-data-cassandra",
    "starter-data-couchbase-reactive",
    "starter-data-couchbase",
    "starter-data-elasticsearch",
    "starter-data-jdbc",
    "starter-data-jpa",
    "starter-data-ldap",
    "starter-data-mongodb-reactive",
    "starter-data-mongodb",
    "starter-data-neo4j",
    "starter-data-r2dbc",
    "starter-data-redis-reactive",
    "starter-data-redis",
    "starter-data-rest",
    "starter-freemarker",
    "starter-groovy-templates",
    "starter-hateoas",
    "starter-integration",
    "starter-jdbc",
    "starter-jetty",
    "starter-jooq",
    "starter-json",
    "starter-log4j2",
    "starter-logging",
    "starter-mail",
    "starter-mustache",
    "starter-oauth2-client",
    "starter-oauth2-resource-server",
    "starter-parent",
    "starter-quartz",
    "starter-reactor-netty",
    "starter-rsocket",
    "starter-security",
    "starter-test",
    "starter-thymeleaf",
    "starter-tomcat",
    "starter-undertow",
    "starter-validation",
    "starter-webflux",
    "starter-web-services",
    "starter-websocket",
    "starter-web",
    "starter",
    # From https://github.com/spring-projects/spring-boot/tree/2.7.x/spring-boot-project/spring-boot-tools
    "antlib",
    "autoconfigure-processor",
    "buildpack-platform",
    "configuration-metadata",
    "configuration-processor",
    "gradle-plugin",
    "gradle-test-support",
    "jarmode-layertools",
    "loader-tools",
    "loader",
    "maven-plugin",
    "test-support",
    # And the spring-boot* ones from https://github.com/spring-projects/spring-boot/tree/1.0.x/ also
    # without the "spring-boot" prefix. Note that some are shared across both lists. Similar to the
    # 2.7.x tree this older tree has also the "spring-boot-starters" and "spring-boot-tools"
    # sub-folders but also another "spring-boot-samples" which are all handled separately in the
    # list below.
    "actuator",
    "autoconfigure",
    "cli",
    "dependencies",
    "docs",
    "full-build",
    "integration-tests",
    "parent",
    # From https://github.com/spring-projects/spring-boot/tree/1.0.x/spring-boot-starters
    "sample-actuator-log4j",
    "sample-actuator-noweb",
    "sample-actuator-ui",
    "sample-actuator",
    "sample-amqp",
    "sample-aop",
    "sample-batch",
    "sample-data-jpa",
    "sample-data-mongodb",
    "sample-data-redis",
    "sample-data-rest",
    "sample-integration",
    "sample-jetty",
    "sample-profile",
    "sample-secure",
    "sample-servlet",
    "sample-simple",
    "sample-tomcat8-jsp",
    "sample-tomcat-multi-connectors",
    "sample-tomcat",
    "sample-traditional",
    "sample-web-jsp",
    "sample-web-method-security",
    "sample-web-secure",
    "sample-websocket",
    "sample-web-static",
    "sample-web-ui",
    "sample-xml",
    # From https://github.com/spring-projects/spring-boot/tree/1.0.x/spring-boot-tools
    "dependency-tools",
    "gradle-plugin",
    "loader-tools",
    "loader",
    "maven-plugin",
    # From https://github.com/spring-projects/spring-boot/tree/1.0.x/spring-boot-starters
    "starter-actuator",
    "starter-amqp",
    "starter-aop",
    "starter-batch",
    "starter-data-jpa",
    "starter-data-mongodb",
    "starter-data-rest",
    "starter-integration",
    "starter-jdbc",
    "starter-jetty",
    "starter-log4j",
    "starter-logging",
    "starter-mobile",
    "starter-parent",
    "starter-redis",
    "starter-remote-shell",
    "starter-security",
    "starter-test",
    "starter-thymeleaf",
    "starter-tomcat",
    "starter-websocket",
    "starter-web",
    "starter" );

  comp_list = make_list_unique( comp_list );

  return comp_list;
}

# @brief Returns a list of known VMware Spring Cloud components.
#
# @return A list of known VMware Spring Cloud components.
#
function spring_cloud_comp_list() {

  local_var comp_list;

  comp_list = make_list(

    # nb: The list should be always sorted in a way that e.g. "skipper-client" is included before
    # "skipper". Otherwise the detection VTs using this in e.g. a regex would extract the wrong
    # component name as the less specific one.

    # All of:
    # https://mvnrepository.com/artifact/org.springframework.cloud
    "app-broker-core",
    "aws-autoconfigure",
    "aws-context",
    "aws-core",
    "aws-jdbc",
    "aws-messaging",
    "bus",
    "cloudfoundry-connector",
    "cloudfoundry-service-broker",
    "cluster-core",
    "commons",
    "config-client",
    "config-monitor",
    "config-server",
    "connectors-core",
    "consul-config",
    "consul-core",
    "consul-discovery",
    "context",
    "contract-converters",
    "contract-shade",
    "contract-spec-java",
    "contract-spec",
    "contract-stub-runner",
    "contract-verifier",
    "contract-wiremock",
    "core",
    "dataflow-admin-starter",
    "dataflow-completion",
    "dataflow-configuration-metadata",
    "dataflow-core",
    "dataflow-module-deployer-spi",
    "dataflow-registry",
    "dataflow-rest-client",
    "dataflow-rest-resource",
    "dataflow-server-core",
    "dataflow-server-local",
    "dataflow-shell-core",
    "dataflow-shell",
    "dependencies",
    "deployer-cloudfoundry",
    "deployer-kubernetes",
    "deployer-local",
    "deployer-resource-docker",
    "deployer-resource-maven",
    "deployer-resource-support",
    "deployer-spi-test",
    "deployer-spi",
    "deployer-yarn",
    "function-context",
    "function-core",
    "function-web",
    "gateway-core",
    "gateway-server",
    "gateway-webflux",
    "gcp-core",
    "gcp-pubsub",
    "gcp-starter-core",
    "gcp-starter-pubsub",
    "gcp-starter-storage",
    "gcp-starter",
    "gcp-storage",
    "huawei-common",
    "kubernetes-client-autoconfig",
    "kubernetes-client-discovery",
    "kubernetes-commons",
    "kubernetes-core",
    "kubernetes-discovery",
    "kubernetes-fabric8-autoconfig",
    "kubernetes-fabric8-config",
    "kubernetes-fabric8-discovery",
    "kubernetes-ribbon",
    "lattice-core",
    "loadbalancer",
    "localconfig-connector",
    "netflix-archaius",
    "netflix-core",
    "netflix-eureka-client",
    "netflix-eureka-server",
    "netflix-hystrix-dashboard",
    "netflix-hystrix-stream",
    "netflix-hystrix",
    "netflix-ribbon",
    "netflix-turbine",
    "netflix-zuul",
    "openfeign-core",
    "open-service-broker-autoconfigure",
    "open-service-broker-core",
    "open-service-broker",
    "scheduler-spi",
    "schema-registry-client",
    "security",
    "service-connector",
    "skipper-client",
    "skipper-platform-cloudfoundry",
    "skipper-platform-kubernetes",
    "skipper-server-core",
    "skipper",
    "sleuth-autoconfigure",
    "sleuth-brave",
    "sleuth-core",
    "sleuth-instrumentation",
    "sleuth-otel",
    "sleuth-stream",
    "sleuth-zipkin",
    "spring-service-connector",
    "square-okhttp",
    "starter-alibaba-nacos-config",
    "starter-alibaba-nacos-discovery",
    "starter-alibaba-sentinel",
    "starter-archaius",
    "starter-aws-messaging",
    "starter-aws",
    "starter-bootstrap",
    "starter-bus-amqp",
    "starter-bus-kafka",
    "starter-circuitbreaker-reactor-resilience4j",
    "starter-circuitbreaker-resilience4j",
    "starter-common-security-config-web",
    "starter-config",
    "starter-consul-all",
    "starter-consul-config",
    "starter-consul-discovery",
    "starter-consul",
    "starter-contract-stub-runner",
    "starter-contract-verifier",
    "starter-dataflow-metrics-collector",
    "starter-dataflow-server-local",
    "starter-eureka-server",
    "starter-eureka",
    "starter-feign",
    "starter-function-web",
    "starter-gateway",
    "starter-hystrix-dashboard",
    "starter-hystrix",
    "starter-kubernetes-all",
    "starter-kubernetes-client-config",
    "starter-kubernetes-config",
    "starter-kubernetes-fabric8-all",
    "starter-kubernetes-fabric8-config",
    "starter-kubernetes-fabric8",
    "starter-kubernetes",
    "starter-loadbalancer",
    "starter-netflix-archaius",
    "starter-netflix-eureka-client",
    "starter-netflix-eureka-server",
    "starter-netflix-hystrix-dashboard",
    "starter-netflix-hystrix",
    "starter-netflix-ribbon",
    "starter-netflix-turbine",
    "starter-netflix-turbine-stream",
    "starter-netflix-zuul",
    "starter-oauth2",
    "starter-openfeign",
    "starter-open-service-broker-webmvc",
    "starter-ribbon",
    "starter-security",
    "starter-sleuth",
    "starter-spectator",
    "starter-stream-kafka",
    "starter-stream-rabbit",
    "starter-task",
    "starter-turbine",
    "starter-vault-config",
    "starter-zipkin",
    "starter-zookeeper-config",
    "starter-zookeeper-discovery",
    "starter-zookeeper",
    "starter-zuul",
    "starter",
    "stream-binder-kafka11-core",
    "stream-binder-kafka-core",
    "stream-binder-kafka-streams",
    "stream-binder-kafka",
    "stream-binder-rabbit-core",
    "stream-binder-rabbit-test-support",
    "stream-binder-rabbit",
    "stream-binder-redis",
    "stream-binder-rocketmq",
    "stream-binder-spi",
    "stream-binder-test",
    "stream-codec",
    "stream-module-launcher",
    "stream-reactive",
    "stream-sample-transform",
    "stream-schema",
    "stream-test-support-internal",
    "stream-test-support",
    "stream",
    "task-batch",
    "task-core",
    "task-stream",
    "test-support",
    "vault-config",
    "zookeeper-core" );

  comp_list = make_list_unique( comp_list );

  return comp_list;
}