// Copyright (c) 2019, 2021, Oracle and/or its affiliates.
// Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.

package oracle.kubernetes.operator.helpers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import io.kubernetes.client.openapi.models.V1EnvVar;

import static oracle.kubernetes.operator.helpers.PodCompatibility.getMissingElements;
import static oracle.kubernetes.weblogic.domain.model.ServerEnvVars.DOMAIN_HOME;
import static oracle.kubernetes.weblogic.domain.model.ServerEnvVars.LOG_HOME;
import static oracle.kubernetes.weblogic.domain.model.ServerEnvVars.SERVER_OUT_IN_POD_LOG;

class CompatibleMaps<K, V> implements CompatibilityCheck {
  private static final List<String> DOMAIN_FIELDS = Collections.singletonList("env");
  private static final List<String> DOMAIN_ENV_KEYS = Arrays.asList(LOG_HOME, SERVER_OUT_IN_POD_LOG, DOMAIN_HOME);
  private static final HashMap<String, String> ELEMENT_NAMES_MAP = new HashMap<>();

  static {
    ELEMENT_NAMES_MAP.put(LOG_HOME, "logHome");
    ELEMENT_NAMES_MAP.put(SERVER_OUT_IN_POD_LOG, "isIncludeServerOutInPodLog");
    ELEMENT_NAMES_MAP.put(DOMAIN_HOME, "domainHome");
  }

  private final String description;
  private final Map<K, V> expected;
  private final Map<K, V> actual;
  private final List<String> ignoredKeys = new ArrayList<>();

  CompatibleMaps(String description, Map<K, V> expected, Map<K, V> actual) {
    this.description = description;
    this.expected = expected;
    this.actual = actual;
  }

  @Override
  public boolean isCompatible() {
    for (K key : expected.keySet()) {
      if (isKeyToCheck(key) && isIncompatible(key)) {
        return false;
      }
    }
    return true;
  }

  private boolean isKeyToCheck(K key) {
    return !ignoredKeys.contains(key.toString());
  }

  private boolean isIncompatible(K key) {
    return !actual.containsKey(key) || valuesDiffer(key);
  }

  private boolean valuesDiffer(K key) {
    return !Objects.equals(expected.get(key), actual.get(key));
  }

  @Override
  public String getIncompatibility() {
    StringBuilder sb = new StringBuilder();

    Set<K> missingKeys = getMissingElements(expected.keySet(), actual.keySet());
    if (!missingKeys.isEmpty()) {
      sb.append(String.format("%s changed and contains '%s' as well%n", description, missingKeys));
    }

    for (K key : expected.keySet()) {
      if (isKeyToCheck(key) && actual.containsKey(key) && valuesDiffer(key)) {
        sb.append(
            String.format(
                "%s '%s' changed from '%s' to '%s'%n",
                description, key, getValue(actual.get(key)), getValue(expected.get(key))));
      }
    }

    return sb.length() == 0 ? null : sb.toString();
  }

  private String getDomainIncompatibility() {
    StringBuilder sb = new StringBuilder();

    Set<K> missingKeys = getMissingElements(expected.keySet(), actual.keySet());
    if (!missingKeys.isEmpty()) {
      sb.append(String.format("%s changed and contains '%s' as well%n", description, missingKeys));
    }

    for (K key : expected.keySet()) {
      if (isKeyToCheck(key) && actual.containsKey(key) && valuesDiffer(key) && isDomainKey(key)) {
        sb.append(
            String.format(
                "'%s' changed from '%s' to '%s'%n",
                ELEMENT_NAMES_MAP.get(key), getValue(actual.get(key)), getValue(expected.get(key))));
      }
    }

    return sb.length() == 0 ? null : sb.toString();
  }

  private Object getValue(Object obj) {
    if (obj instanceof V1EnvVar) {
      return ((V1EnvVar) obj).getValue();
    }
    return obj;
  }

  private String getUnknownIncompatibility() {
    StringBuilder sb = new StringBuilder();


    Set<K> missingKeys = getMissingElements(expected.keySet(), actual.keySet());
    if (!missingKeys.isEmpty()) {
      sb.append(String.format("%s changed and contains '%s' as well%n", description, missingKeys));
    }

    for (K key : expected.keySet()) {
      if (isKeyToCheck(key) && actual.containsKey(key) && valuesDiffer(key) && !isDomainKey(key)) {
        sb.append(
            String.format(
                "%s '%s' changed from '%s' to '%s'%n",
                description, key, actual.get(key), expected.get(key)));
      }
    }

    return sb.length() == 0 ? null : sb.toString();
  }

  private boolean isDomainKey(K key) {
    return DOMAIN_ENV_KEYS.contains(key);
  }

  private boolean containsDomainKeys(Set<K> missingKeys) {
    for (K key : missingKeys) {
      if (isDomainKey(key)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public String getScopedIncompatibility(CompatibilityScope scope) {
    switch (scope) {
      case DOMAIN:
        return getDomainIncompatibility();
      case UNKNOWN:
        return getUnknownIncompatibility();
      case POD:
        return getIncompatibility();
      default:
        return null;
    }
  }

  @Override
  public CompatibilityScope getScope() {
    if (DOMAIN_FIELDS.contains(description)) {
      return CompatibilityScope.MINIMUM;
    }
    return CompatibilityScope.UNKNOWN;
  }

  @Override
  public CompatibilityCheck ignoring(String... keys) {
    ignoredKeys.addAll(Arrays.asList(keys));
    return this;
  }
}
